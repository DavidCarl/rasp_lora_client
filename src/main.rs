extern crate linux_embedded_hal as hal;
extern crate sx127x_lora;

use std::fmt;
use std::{error::Error as stdError, result::Result};

use std::{thread, time};

// RANDOM

use rand::{rngs::StdRng, Rng, SeedableRng};
use x25519_dalek_ng::{PublicKey, StaticSecret};

// EDHOC

use oscore::edhoc::{
    api::{Msg1Sender, Msg2Receiver, Msg4ReceiveVerify},
    error::{OwnError, OwnOrPeerError},
    PartyI,
};

// Ratchet

use twoRatchet::ratchfuncs::state;

// LORA MODULE

use sx127x_lora::LoRa;

const LORA_CS_PIN: u8 = 8;
const LORA_RESET_PIN: u8 = 22;
const FREQUENCY: i64 = 915;

// HAL

use rppal::gpio::{Gpio, OutputPin};
use rppal::hal::Delay;
use rppal::spi::{Bus, Mode, SlaveSelect, Spi};

// JSON AND FILES

use std::collections::HashMap;
use std::fs;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    data: HashMap<String, Device>,
    deveui: Vec<Vec<u8>>,
    appeui: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Device {
    key: Vec<u8>
}

const SUITE_I: u8 = 3;
const METHOD_TYPE_I: u8 = 0;

#[derive(Serialize, Deserialize, Debug)]
struct StaticKeys {
    r_static_material: [u8; 32],
    i_static_material: [u8; 32]
} 

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    deveui: [u8; 8],
    appeui: [u8; 8],
    dhr_const: u16,
    rx1_delay: u64,
    rx1_duration: i32,
    rx2_delay: u64,
    rx2_duration: i32
}

static mut FCNTUP: u16 = 0;
static mut DEVADDR: [u8; 4] = [0, 0, 0, 0];

#[derive(Debug)]
struct MyError(String);

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "There is an error: {}", self.0)
    }
}

impl stdError for MyError {}

struct MessageStruct {
    _m: u8,
    _fcntdown: [u8; 2],
    devaddr: [u8; 4],
    msg: Vec<u8>,
}

struct RatchetKeys {
    ed_sck: Vec<u8>,
    ed_rck: Vec<u8>,
    ed_rk: Vec<u8>,
    devaddr: Vec<u8>,
}

fn main() {
    let config: Config = load_config("./config.json".to_string());
    let enc_keys: StaticKeys = load_static_keys("./keys.json".to_string());
    let mut lora = setup_sx127x(125000, 7);
    let rtn = edhoc_handshake(lora, enc_keys, config.deveui, config.appeui).unwrap();
    lora_ratchet(rtn, config.dhr_const);
}

fn load_file(path: String) -> String {
    fs::read_to_string(path).expect("Unable to read file")
}

fn load_static_keys(path: String) -> StaticKeys {
    let static_data = load_file(path);
    let static_keys: StaticKeys = serde_json::from_str(&static_data).unwrap();
    static_keys
}

fn load_config(path: String) -> Config {
    let config_data = load_file(path);
    let config: Config = serde_json::from_str(&config_data).unwrap();
    config
}

fn lora_ratchet(rtn: EdhocHandshake, dhr_const: u16) {
    let mut lora = rtn.lora;

    let mut i_ratchet = state::init_i(
        rtn.ratchet_keys.ed_rk.try_into().unwrap(),
        rtn.ratchet_keys.ed_rck.try_into().unwrap(),
        rtn.ratchet_keys.ed_sck.try_into().unwrap(),
        rtn.ratchet_keys.devaddr.clone(),
    );
    
    for n in 1..18000 {
        let uplink = i_ratchet.ratchet_encrypt_payload(&[1; 34], &rtn.ratchet_keys.devaddr);
        let (msg_uplink, len_uplink) = lora_send(uplink);
        let transmit = lora.transmit_payload_busy(msg_uplink, len_uplink);
        match transmit {
            Ok(packet_size) => {
                println!("Sent packet with size: {:?}", packet_size)
            }
            Err(_) => println!("Error uplink"),
        }

        let ten_millis = time::Duration::from_millis(10000);

        thread::sleep(ten_millis);

        if i_ratchet.fcnt_send >= dhr_const {
            let dhr_req = i_ratchet.i_initiate_ratch();
            let (msg_dhr_req, len_dhr_req) = lora_send(dhr_req);
            let transmit = lora.transmit_payload_busy(msg_dhr_req, len_dhr_req);
            match transmit {
                Ok(packet_size) => {
                    println!("Sent packet with size: {:?}", packet_size)
                }
                Err(er) => println!("Error {:?}, {:?}", n, er),
            }
            let poll = lora.poll_irq(Some(5000), &mut Delay);
            match poll {
                Ok(size) => {
                    println!("Recieved packet with size: {:?}", size);
                    let buffer = lora.read_packet().unwrap();
                    let dhr_ack = &buffer; // if this is not the dhrack, it will still be decrypted and handled
                    match i_ratchet.i_receive(dhr_ack.to_vec()) {
                        Some(x) => {
                            println!("receiving message from server {:?}", x)
                        }
                        None => continue,
                    };
                }
                _ => println!("Error happened at DHR_REQ"),
            }
        } else {
            let poll = lora.poll_irq(Some(5000), &mut Delay);
            match poll {
                Ok(size) => {
                    println!("Recieved packet with size: {:?}", size);
                    let buffer = lora.read_packet().unwrap();
                    let downlink = &buffer; // if this is not the dhrack, it will still be decrypted and handled
                    match i_ratchet.i_receive(downlink.to_vec()) {
                        Some(x) => {
                            println!("receiving message from server {:?}", x)
                        }
                        None => continue,
                    };
                }
                _ => println!("Error happened at DHR_REQ"),
            }
        }
    }
}

struct EdhocHandshake {
    lora: LoRa<Spi, OutputPin, OutputPin>, 
    ratchet_keys: RatchetKeys
}

fn edhoc_handshake(
    mut lora: LoRa<Spi, OutputPin, OutputPin>,
    enc_keys: StaticKeys,
    deveui: [u8; 8],
    appeui: [u8; 8]
) -> Result<EdhocHandshake, Box<dyn stdError>> {
    let i_kid = [0xA2].to_vec();
    let i_static_priv = StaticSecret::from(enc_keys.i_static_material);
    let i_static_pub = PublicKey::from(&i_static_priv);
    let r_static_pub = PublicKey::from(enc_keys.r_static_material);
    // create ehpemeral key material
    let mut r: StdRng = StdRng::from_entropy();
    let i_ephemeral_keying = r.gen::<[u8; 32]>();

    let msg1_sender = PartyI::new(
        deveui.to_vec(),
        appeui.to_vec(),
        i_ephemeral_keying,
        i_static_priv,
        i_static_pub,
        i_kid,
    );
    let (payload1, msg2_reciever) = edhoc_first_message(msg1_sender);
    let (msg, len) = lora_send(payload1);

    let transmit = lora.transmit_payload_busy(msg, len);
    match transmit {
        Ok(packet_size) => println!("Sent packet with size: {:?}", packet_size),
        Err(_) => println!("Error"),
    }

    let poll = lora.poll_irq(Some(5000), &mut Delay);
    match poll {
        Ok(size) => {
            println!("Recieved packet with size: {:?}", size);
            let buffer = lora.read_packet().unwrap();
            match buffer[0] {
                1 => {
                    match edhoc_third_message(buffer.to_vec(), msg2_reciever, r_static_pub) {
                        Ok((msg3, msg4_reciever)) => {
                            let (msg, len) = lora_send(msg3);
                            let transmit = lora.transmit_payload_busy(msg, len);
                            match transmit {
                                Ok(packet_size) => {
                                    println!("Sent packet with size: {:?}", packet_size)
                                }
                                Err(_) => println!("Error"),
                            }
                            let poll = lora.poll_irq(Some(5000), &mut Delay);
                            match poll {
                                Ok(size) => {
                                    println!("Recieved packet with size: {:?}", size);
                                    let buffer = lora.read_packet().unwrap();
                                    match buffer[0] {
                                        3 => {
                                            let (ed_sck, ed_rck, ed_rk, devaddr) =
                                                handle_message_fourth(buffer, msg4_reciever);
                                            let ratchet_keys = RatchetKeys {
                                                ed_sck,
                                                ed_rck,
                                                ed_rk,
                                                devaddr,
                                            };
                                            Ok(EdhocHandshake{lora, ratchet_keys})
                                        }
                                        _ => {
                                            Err(Box::new(MyError(
                                                "Wrong order, got some other message than mtype 3"
                                                    .to_string(),
                                            )))
                                        }
                                    }
                                }
                                Err(_) => Err(Box::new(MyError(
                                    "Recieved nothing in our allocated time span".to_string(),
                                ))),
                            }
                        }
                        Err(OwnOrPeerError::PeerError(x)) => {
                            Err(Box::new(MyError(x)))
                        }
                        Err(OwnOrPeerError::OwnError(_)) => {
                            Err(Box::new(MyError("Own error".to_string())))
                        }
                    }
                }
                _ => Err(Box::new(MyError(
                    "Wrong order, got some other message than mtype 1".to_string(),
                ))),
            }
        }
        Err(_) => Err(Box::new(MyError(
            "Recieved nothing in our allocated time span".to_string(),
        ))),
    }
}

fn edhoc_first_message(msg1_sender: PartyI<Msg1Sender>) -> (Vec<u8>, PartyI<Msg2Receiver>) {
    let (msg1_bytes, msg2_receiver) =
    // If an error happens here, we just abort. No need to send a message,
    // since the protocol hasn't started yet.
    msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();

    let payload1 = prepare_message(msg1_bytes, 0, true);
    (payload1, msg2_receiver)
}

fn edhoc_third_message(
    msg2: Vec<u8>,
    msg2_receiver: PartyI<Msg2Receiver>,
    r_static_pub: PublicKey,
) -> Result<(Vec<u8>, PartyI<Msg4ReceiveVerify>), OwnOrPeerError> {
    let msg_struc = remove_message(msg2);
    unsafe {
        DEVADDR = msg_struc.devaddr;
    }

    // read from file, and check what key responds to r_kid
    // Needs to be used when verififying message2 instead of &r_static_pub.as_bytes()
    let (_r_kid, _ad_r, msg2_verifier) =
        match msg2_receiver.unpack_message_2_return_kid(msg_struc.msg) {
            Err(OwnOrPeerError::PeerError(s)) => {
                return Err(OwnOrPeerError::PeerError(s));
            }
            Err(OwnOrPeerError::OwnError(b)) => {
                return Err(OwnOrPeerError::OwnError(b));
            }
            Ok(val) => val,
        };
    // I has now received the r_kid, such that the can retrieve the static key of r, and verify the first message

    let msg3_sender = match msg2_verifier.verify_message_2(&r_static_pub.as_bytes().to_vec()) {
        Err(OwnError(b)) => {
            return Err(OwnOrPeerError::OwnError(b));
        }
        Ok(val) => val,
    };

    let (msg4_receiver_verifier, msg3_bytes) = match msg3_sender.generate_message_3() {
        Err(OwnError(b)) => {
            return Err(OwnOrPeerError::OwnError(b));
        }
        Ok(val) => val,
    };

    let payload3 = prepare_message(msg3_bytes, 2, false);
    Ok((payload3, msg4_receiver_verifier))
}

fn handle_message_fourth(
    msg: Vec<u8>,
    msg4_receiver_verifier: PartyI<Msg4ReceiveVerify>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let msg_struc = remove_message(msg);
    let out = msg4_receiver_verifier.receive_message_4(msg_struc.msg);
    let out = match out {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };
    let (ed_sck, ed_rck, ed_rk) = out;

    (ed_sck, ed_rck, ed_rk, msg_struc.devaddr.to_vec())
}

struct ReceiveWindow {
    lora: LoRa<Spi, OutputPin, OutputPin>,
    buffer: Vec<u8>
}

fn recieve_window(mut lora: LoRa<Spi, OutputPin, OutputPin>, config: Config) -> Result<ReceiveWindow, Box<dyn stdError>> {
    thread::sleep(time::Duration::from_millis(config.rx1_delay));
    let poll = lora.poll_irq(Some(config.rx1_duration), &mut Delay);
    match poll {
        Ok(size) => {
            let buffer = lora.read_packet().unwrap();
            println!("Recieved packet with size: {:?}", size);
            Ok(ReceiveWindow{lora, buffer})
        }
        Err(_) => {
            thread::sleep(time::Duration::from_millis(config.rx1_delay));
            let poll = lora.poll_irq(Some(config.rx1_duration), &mut Delay);
            match poll {
                Ok(size) => {
                    let buffer = lora.read_packet().unwrap();
                    println!("Recieved packet with size: {:?}", size);
                    Ok(ReceiveWindow{lora, buffer})
                }
                Err(_) => {
                    Err(Box::new(MyError(
                        "Recieved nothing in our rx1 or rx2".to_string(),
                    )))
                }
            }
        }
    }
}

fn remove_message(ogmsg: Vec<u8>) -> MessageStruct {
    MessageStruct {
        _m: ogmsg[0],
        _fcntdown: ogmsg[1..3].try_into().unwrap(),
        devaddr: ogmsg[3..7].try_into().unwrap(),
        msg: ogmsg[7..].try_into().unwrap(),
    }
}

fn prepare_message(msg: Vec<u8>, mtype: u8, first_msg: bool) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&mtype.to_be_bytes());
    unsafe {
        buffer.extend_from_slice(&FCNTUP.to_be_bytes());
        FCNTUP += 1;
    }
    if !first_msg {
        unsafe {
            buffer.extend_from_slice(&DEVADDR);
        }
    }
    buffer.extend_from_slice(&msg);
    buffer
}

fn setup_sx127x(bandwidth: i64, spreadfactor: u8) -> LoRa<Spi, OutputPin, OutputPin> {
    let spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, 8_000_000, Mode::Mode0).unwrap();

    let gpio = Gpio::new().unwrap();

    let cs = gpio.get(LORA_CS_PIN).unwrap().into_output();
    let reset = gpio.get(LORA_RESET_PIN).unwrap().into_output();

    let mut lora = sx127x_lora::LoRa::new(spi, cs, reset, FREQUENCY, &mut Delay).unwrap();
    //let _ = lora.set_signal_bandwidth()
    let _ = lora.set_signal_bandwidth(bandwidth);
    let _ = lora.set_spreading_factor(spreadfactor);
    lora
}

fn lora_send(message: Vec<u8>) -> ([u8; 255], usize) {
    let mut buffer = [0; 255];
    for (i, byte) in message.iter().enumerate() {
        buffer[i] = *byte;
    }
    (buffer, message.len())
}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}

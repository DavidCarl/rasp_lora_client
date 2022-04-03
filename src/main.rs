extern crate linux_embedded_hal as hal;
extern crate sx127x_lora;

use std::result::Result;

// RANDOM

use rand::{rngs::StdRng, Rng, SeedableRng};
use x25519_dalek_ng::{PublicKey, StaticSecret};

// EDHOC

use oscore::edhoc::{
    api::{Msg1Sender, Msg2Receiver, Msg4ReceiveVerify},
    error::{Error, OwnError, OwnOrPeerError},
    util::build_error_message,
    PartyI,
};

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
    key: Vec<u8>,
}

const SUITE_I: isize = 3;
const METHOD_TYPE_I: isize = 0;

const I_STATIC_MATERIAL: [u8; 32] = [
    154, 31, 220, 202, 59, 128, 114, 237, 96, 201, 18, 178, 29, 143, 85, 133, 70, 32, 155, 41, 124,
    111, 51, 127, 254, 98, 103, 99, 0, 38, 102, 4,
];

const R_STATIC_MATERIAL: [u8; 32] = [
    245, 156, 136, 87, 191, 59, 207, 135, 191, 100, 46, 213, 24, 152, 151, 45, 141, 35, 185, 103,
    168, 73, 74, 231, 37, 220, 227, 42, 68, 62, 196, 109,
];

const DEVEUI: [u8; 8] = [0x1, 1, 2, 3, 2, 4, 5, 7];
const APPEUI: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

static mut FCNTUP: u16 = 0;
static mut DEVADDR: [u8; 4] = [0,0,0,0];

fn main() {
    println!("Hello, world!");
    let lora = setup_sx127x();
    edhoc_handshake(lora);
}

fn load_file(path: String) -> String {
    let data = fs::read_to_string(path).expect("Unable to read file");
    //rintln!("{}", data);
    data
}

fn edhoc_handshake(mut lora: LoRa<Spi, OutputPin, OutputPin>) {
    // Sender besked til server - Send
    // Modtager besked fra server - Listen
    // Sender til server - Send
    // Modtager fra server - Listen
    // klar til at sende diverse beskeder

    let i_kid = [0xA2].to_vec();
    let i_static_priv = StaticSecret::from(I_STATIC_MATERIAL);
    let i_static_pub = PublicKey::from(&i_static_priv);
    let r_static_pub = PublicKey::from(R_STATIC_MATERIAL);
    // create ehpemeral key material
    let mut r: StdRng = StdRng::from_entropy();
    let i_ephemeral_keying = r.gen::<[u8; 32]>();

    let msg1_sender = PartyI::new(
        DEVEUI.to_vec(),
        APPEUI.to_vec(),
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
        Ok(_size) => {
            let buffer = lora.read_packet().unwrap(); // Received buffer. NOTE: 255 bytes are always returned
            println! {"{:?}", buffer}
            match buffer[0] {
                1 => {
                    let msg = &buffer[1..];
                    //let (msg3, Msg4_Reciever) = 
                    match edhoc_third_message(msg.to_vec(), msg2_reciever, r_static_pub) {
                        Ok((msg3, Msg4_Reciever)) => {
                            let (msg, len) = lora_send(msg3);
                            let transmit = lora.transmit_payload_busy(msg, len);
                            match transmit {
                                Ok(packet_size) => println!("Sent packet with size: {:?}", packet_size),
                                Err(_) => println!("Error"),
                            }
                        }
                        Err(OwnOrPeerError::PeerError(x)) => {
                            println!("Something went horrible wrong! {:?}", x)
                        }
                        Err(OwnOrPeerError::OwnError(x)) => {
                            println!("TODO: Send error message")
                        }
                    }
                }
                _ => println!("VAGT I GEVÆRET, NOGLE SNYDER"),
            }
        }
        Err(_) => println!("Timeout"),
    }
}

fn edhoc_first_message(msg1_sender: PartyI<Msg1Sender>) -> (Vec<u8>, PartyI<Msg2Receiver>) {
    let (msg1_bytes, msg2_receiver) =
    // If an error happens here, we just abort. No need to send a message,
    // since the protocol hasn't started yet.
    msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();

    println!("msg1 sent {:?}", msg1_bytes);
    println!("msg1 len {:?}", msg1_bytes.len());

    // adding mtype
    //    let mut payload1 = [0].to_vec();
    //    payload1.extend(msg1_bytes);
    let payload1 = prepare_message(msg1_bytes, 0, true);
    (payload1, msg2_receiver)
}

fn edhoc_third_message(
    msg2: Vec<u8>,
    msg2_receiver: PartyI<Msg2Receiver>,
    mut r_static_pub: PublicKey,
) -> Result<(Vec<u8>, PartyI<Msg4ReceiveVerify>), OwnOrPeerError> {
    println!("");
    println!("msg2.len before removing devaddr {:?} ", msg2.len());
    unsafe {
        DEVADDR = msg2[0..4].try_into().unwrap();
        println!("\nDevAdrr {:?}\n", DEVADDR);
    }
    let msg2 = remove_devaddr(msg2);
    println!("msg2.len {:?} ", msg2.len());
    println!("msg2 {:?} ", msg2);


    // read from file, and check what key responds to r_kid
    // Needs to be used when verififying message2 instead of &r_static_pub.as_bytes()
    let (r_kid, ad_r, msg2_verifier) =
        match msg2_receiver.unpack_message_2_return_kid(msg2) {
            Err(OwnOrPeerError::PeerError(s)) => return Err(OwnOrPeerError::PeerError(s)),
            Err(OwnOrPeerError::OwnError(b)) => {
                println!("First attempt at dying");
                //return Ok(b)
                println!("{:?}", &b);
                return Err(OwnOrPeerError::OwnError(b));
            }
            Ok(val) => val,
        };
    // I has now received the r_kid, such that the can retrieve the static key of r, and verify the first message

    let msg3_sender = match msg2_verifier.verify_message_2(&r_static_pub.as_bytes().to_vec()) {
        Err(OwnError(b)) => {
            println!("Or here");
            //return Ok(b)},
            return Err(OwnOrPeerError::OwnError(b));
        }
        Ok(val) => val,
    };

    let (msg4_receiver_verifier, msg3_bytes) = match msg3_sender.generate_message_3() {
        Err(OwnError(b)) => {
            println!(" am i dying here?");
            //panic!("Send these bytes: {}", hexstring(&b))
            return Err(OwnOrPeerError::OwnError(b));
        }
        Ok(val) => val,
    };

    // sending message 2
    let mut payload3 = [2].to_vec();
    payload3.extend(msg3_bytes);
    Ok((payload3, msg4_receiver_verifier))
}

fn remove_devaddr(msg: Vec<u8>) -> Vec<u8>{
    msg[4..].to_vec()
}

fn prepare_message(msg: Vec<u8>, mtype: u8, first_msg: bool) -> Vec<u8>{
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

fn setup_sx127x() -> LoRa<Spi, OutputPin, OutputPin> {
    let spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, 8_000_000, Mode::Mode0).unwrap();

    let gpio = Gpio::new().unwrap();

    let cs = gpio.get(LORA_CS_PIN).unwrap().into_output();
    let reset = gpio.get(LORA_RESET_PIN).unwrap().into_output();

    sx127x_lora::LoRa::new(spi, cs, reset, FREQUENCY, &mut Delay).unwrap()
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
#![allow(clippy::single_component_path_imports)]
//#![feature(backtrace)]

#[cfg(all(feature = "qemu", not(esp32)))]
compile_error!("The `qemu` feature can only be built for the `xtensa-esp32-espidf` target.");

#[cfg(all(feature = "ip101", not(esp32)))]
compile_error!("The `ip101` feature can only be built for the `xtensa-esp32-espidf` target.");

#[cfg(all(feature = "kaluga", not(esp32s2)))]
compile_error!("The `kaluga` feature can only be built for the `xtensa-esp32s2-espidf` target.");

#[cfg(all(feature = "ttgo", not(esp32)))]
compile_error!("The `ttgo` feature can only be built for the `xtensa-esp32-espidf` target.");

#[cfg(all(feature = "heltec", not(esp32)))]
compile_error!("The `heltec` feature can only be built for the `xtensa-esp32-espidf` target.");

#[cfg(all(feature = "esp32s3_usb_otg", not(esp32s3)))]
compile_error!(
    "The `esp32s3_usb_otg` feature can only be built for the `xtensa-esp32s3-espidf` target."
);
extern crate  alloc;
use rand::{rngs};

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::{cell::RefCell, env,  sync::Arc, thread, time::*};
use std::convert::TryInto;
use std::time::Duration;
use anyhow::bail;


use embedded_svc::httpd::*;
use embedded_svc::ipv4;
use embedded_svc::ping::Ping;

use embedded_svc::wifi::*;


use esp_idf_svc::netif::*;
use esp_idf_svc::nvs::*;
use esp_idf_svc::ping;
use esp_idf_svc::sysloop::*;

use esp_idf_svc::wifi::*;

use esp_idf_hal::prelude::*;

use esp_idf_sys::{self,c_types};

use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI, PartyR,
    util::{build_error_message}
};
use twoRatchet::ratchfuncs::{state};

use rand::{rngs::StdRng, Rng,SeedableRng};

use x25519_dalek_ng::{PublicKey,StaticSecret};

const LEN : usize = 50;

const SUITE_I: isize = 3;
const METHOD_TYPE_I : isize = 0;
const DHR_CONST : u16 = 1;

const I_STATIC_MATERIAL :[u8;32] = [154, 31, 220, 202, 59, 128, 114, 237, 96, 201, 
18, 178, 29, 143, 85, 133, 70, 32, 155, 41, 124, 
111, 51, 127, 254, 98, 103, 99, 0, 38, 102, 4];

const R_STATIC_MATERIAL : [u8;32]= [245, 156, 136, 87, 191, 59, 207, 135, 191, 100, 46,
213, 24, 152, 151, 45, 141, 35, 185, 103, 168, 73, 74, 
231, 37, 220, 227, 42, 68, 62, 196, 109];


const DEVEUI : [u8;8] = [0x1,1,2,3,2,4,5,7];
const APPEUI : [u8;8] = [0,1,2,3,4,5,6,7];





#[cfg(not(feature = "qemu"))]
const SSID: &str = env!("RUST_ESP32_STD_DEMO_WIFI_SSID");
#[cfg(not(feature = "qemu"))]
const PASS: &str = env!("RUST_ESP32_STD_DEMO_WIFI_PASS");

#[cfg(esp32s2)]
include!(env!("EMBUILD_GENERATED_SYMBOLS_FILE"));

#[cfg(esp32s2)]
const ULP: &[u8] = include_bytes!(env!("EMBUILD_GENERATED_BIN_FILE"));



fn main() -> Result<()> {

    esp_idf_sys::link_patches();


    #[allow(unused)]
    let netif_stack = Arc::new(EspNetifStack::new()?);
    #[allow(unused)]
    let sys_loop_stack = Arc::new(EspSysLoopStack::new()?);
    #[allow(unused)]
    let default_nvs = Arc::new(EspDefaultNvs::new()?);


    #[allow(clippy::redundant_clone)]
    #[cfg(not(feature = "qemu"))]
    #[allow(unused_mut)]
    let mut wifi = wifi(
        netif_stack.clone(),
        sys_loop_stack.clone(),
        default_nvs.clone(),
    )?;


   match TcpStream::connect("192.168.1.227:8888") {
        Ok(mut stream) => {
        handle_connection(stream)
        }
        Err(e) => {
            bail!("no succes");
        }
    };


    Ok(())
}


fn handle_connection(mut stream: TcpStream)-> Result<(), Error>   {
    let i_kid = [0xA2].to_vec();
    let i_static_priv = StaticSecret::from(I_STATIC_MATERIAL);
    let i_static_pub = PublicKey::from(&i_static_priv);
    let r_static_pub = PublicKey::from(R_STATIC_MATERIAL);
    // select a connection identifier
    let i_c_i = [0x1].to_vec();
    let i_c_i_cpy = i_c_i.clone();
    // create ehpemeral key material 
    let mut r : StdRng = StdRng::from_entropy();
    let i_ephemeral_keying = r.gen::<[u8;32]>();

    let msg1_sender =
    PartyI::new(DEVEUI.to_vec(), APPEUI.to_vec(), i_ephemeral_keying, i_static_priv, i_static_pub, i_kid);

    let (msg1_bytes, msg2_receiver) =
    // If an error happens here, we just abort. No need to send a message,
    // since the protocol hasn't started yet.
    msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();
    // adding mtype
    let mut payload1 = [0].to_vec();
    payload1.extend(msg1_bytes);
    // sending msg1
    stream.write(&payload1).unwrap();

    let mut buf = [0;128];
    let bytes_read = stream.read(&mut buf)?;
    let msg2 = &buf[0..bytes_read];
    println!("msg2 {:?}", msg2);

    // checking mtype for message 2
    if msg2[0] != 1 {
        println!("receving bad mtype for message 2, closing connection...");
        let err = build_error_message("bad mtype");
        println!("bad mtype");
        stream.write(&err)?;
        return Ok(())

    }
    let devaddr = &msg2[1..5];
    let msg2 = &msg2[5..];
    println!("msg2 {:?} ", msg2);
    
    let  (r_kid, ad_r,msg2_verifier) = match msg2_receiver.unpack_message_2_return_kid(msg2.to_vec()){
        Err(OwnOrPeerError::PeerError(s)) => {
            return Ok(())
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            stream.write(&b)?;// in this case, return this errormessage
            return Ok(())
        } 
        Ok(val) => val,
    }; 
    
    // I has now received the r_kid, such that the can retrieve the static key of r, and verify the first message

    let msg3_sender = match msg2_verifier.verify_message_2(&r_static_pub.as_bytes().to_vec()) {
        Err(OwnError(b)) => {
            stream.write(&b)?;
            return Ok(())},
        Ok(val) => val, };

    // now that the fields of message 2 has been fully verified, I can generate message 3
    
    let (msg4_receiver_verifier, msg3_bytes) =
        match msg3_sender.generate_message_3() {
            Err(OwnError(b)) => {
                println!(" am i dying here?");
                panic!("Send these bytes: {}", hexstring(&b))},
            Ok(val) => val,
        };

    // sending message 2
    let mut payload3 = [2].to_vec();
    payload3.extend(msg3_bytes);
    stream.write(&payload3)?;


    let mut buf = [0;128];
    // read message 1
    let bytes_read = stream.read(&mut buf)?;
    let msg4 = &buf[0..bytes_read];
    println!("msg4 {:?}", msg4);

    if msg4[0] != 3 {
        println!("receving bad mtype for message 4, closing connection...");
        let err = build_error_message("bad mtype");
        stream.write(&err)?;
        return Ok(())
    }
    let msg4 = msg4[1..].to_vec();
    let out = msg4_receiver_verifier.receive_message_4(msg4);
    let out = match out {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };
    let (ed_sck,ed_rck,ed_rk) = out;

    let  mut i_ratchet = state::init_i(ed_rk.try_into().unwrap(),ed_rck.try_into().unwrap(), ed_sck.try_into().unwrap(),devaddr.to_vec());
    stream.set_read_timeout(Some(Duration::new(3, 0)));
    
    for n in 1..18000 {
        stream.set_read_timeout(None);
        thread::sleep(Duration::from_millis(1000));
        let uplink = i_ratchet.ratchet_encrypt_payload(&[1;34], &devaddr);
        println!("uplink");

        stream.write_all(&uplink);
        stream.flush();
        

        if i_ratchet.fcnt_send >= DHR_CONST{
            let dhr_req = i_ratchet.i_initiate_ratch();
            stream.write_all(&dhr_req);
            stream.flush();
            let bytes_read = match stream.read(&mut buf){
                Ok(bytes) => bytes,
                _ => continue,
            };
            let dhr_ack = &buf[0..bytes_read]; // if this is not the dhrack, it will still be decrypted and handled
            match i_ratchet.i_receive(dhr_ack.to_vec()) {
                Some(x) => {println!("receiving message from server {:?}", x)},
                None => continue,
            };
        } else {
             
            // if we do not want to send a DHReq, then we'll just listen for a message
            let bytes_read = match stream.read(&mut buf) {
                Ok(bytes) => bytes,
                _ => continue,
            };
            let downlink = &buf[0..bytes_read]; // if this is not the dhrack, it will still be decrypted and handled
            match i_ratchet.i_receive(downlink.to_vec()) {
                Some(x) => {println!("receiving message from server {:?}", x)},
                None => continue,
            };
        }
    }

    return Ok(())

}



fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}





#[cfg(not(feature = "qemu"))]
#[allow(dead_code)]
fn wifi(
    netif_stack: Arc<EspNetifStack>,
    sys_loop_stack: Arc<EspSysLoopStack>,
    default_nvs: Arc<EspDefaultNvs>,
) -> Result<Box<EspWifi>> {
    let mut wifi = Box::new(EspWifi::new(netif_stack, sys_loop_stack, default_nvs)?);

    println!("Wifi created, about to scan");

    let ap_infos = wifi.scan()?;

    let ours = ap_infos.into_iter().find(|a| a.ssid == SSID);

    let channel = if let Some(ours) = ours {
        println!(
            "Found configured access point {} on channel {}",
            SSID, ours.channel
        );
        Some(ours.channel)
    } else {
        println!(
            "Configured access point {} not found during scanning, will go with unknown channel",
            SSID
        );
        None
    };

    wifi.set_configuration(&Configuration::Mixed(
        ClientConfiguration {
            ssid: SSID.into(),
            password: PASS.into(),
            channel,
            ..Default::default()
        },
        AccessPointConfiguration {
            ssid: "aptest".into(),
            channel: channel.unwrap_or(1),
            ..Default::default()
        },
    ))?;

    println!("Wifi configuration set, about to get status");

    wifi.wait_status_with_timeout(Duration::from_secs(20), |status| !status.is_transitional())
        .map_err(|e| anyhow::anyhow!("Unexpected Wifi status: {:?}", e))?;

    let status = wifi.get_status();

    if let Status(
        ClientStatus::Started(ClientConnectionStatus::Connected(ClientIpStatus::Done(ip_settings))),
        ApStatus::Started(ApIpStatus::Done),
    ) = status
    {
        println!("Wifi connected");

        ping(&ip_settings)?;
    } else {
        bail!("Unexpected Wifi status: {:?}", status);
    }

    Ok(wifi)
}


fn ping(ip_settings: &ipv4::ClientSettings) -> Result<()> {
    println!("About to do some pings for {:?}", ip_settings);

    let ping_summary =
        ping::EspPing::default().ping(ip_settings.subnet.gateway, &Default::default())?;
    if ping_summary.transmitted != ping_summary.received {
        bail!(
            "Pinging gateway {} resulted in timeouts",
            ip_settings.subnet.gateway
        );
    }

    println!("Pinging done");

    Ok(())
}



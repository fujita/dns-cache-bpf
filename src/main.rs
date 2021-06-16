/*
 * Copyright (C) 2021 The dns-cache-bpf Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

use byteorder::{NativeEndian, ReadBytesExt};
use clap::{App, Arg};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[path = "bpf/.output/dns_cache.skel.rs"]
mod dns_cache;
use dns_cache::*;

fn bump_memlock_rlimit() {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        panic!("Failed to increase rlimit");
    }
}

unsafe fn as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

fn main() {
    let args = App::new("dns-cache")
        .arg(
            Arg::with_name("DEV")
                .long("dev")
                .takes_value(true)
                .required(true)
                .help("specify device name (e.g, eth0)"),
        )
        .get_matches();

    let dev_name = CString::new(args.value_of("DEV").unwrap()).unwrap();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let mut builder = DnsCacheSkelBuilder::default();
    builder.obj_builder.debug(true);

    bump_memlock_rlimit();
    let open_skel = builder.open().unwrap();
    let mut skel = open_skel.load().unwrap();

    let ifidx = unsafe { libc::if_nametoindex(dev_name.into_raw()) };
    let p = skel.obj.prog_mut("xdp_dns_handler").unwrap();

    unsafe {
        let r = libbpf_sys::bpf_set_link_xdp_fd(ifidx as i32, p.fd(), 0);
        if r < 0 {
            panic!("failed to attach");
        }
    };

    println!("\nDNS cache started");
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(30));

        let hit = 0;
        let map = skel.obj.map("statsmap").unwrap();
        let v = map
            .lookup(unsafe { as_u8_slice(&hit) }, libbpf_rs::MapFlags::ANY)
            .unwrap()
            .unwrap();
        let num_hit = v.as_slice().read_u64::<NativeEndian>().unwrap();
        let miss = 1;
        let v = map
            .lookup(unsafe { as_u8_slice(&miss) }, libbpf_rs::MapFlags::ANY)
            .unwrap()
            .unwrap();
        let num_miss = v.as_slice().read_u64::<NativeEndian>().unwrap();

        println!("cache hit: {}, miss {}", num_hit, num_miss);
    }
}

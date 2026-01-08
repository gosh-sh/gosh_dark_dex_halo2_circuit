
pub fn consume_uint128_10(b: &[u8]) -> u128 {
    if b.len() < 10 {
        //return Err("Not enough bytes for u64".into());
        panic!("Not enough bytes for u64");
    }
    let result = (b[0] as u128)
        | ((b[1] as u128) << 8)
        | ((b[2] as u128) << 16)
        | ((b[3] as u128) << 24)
        | ((b[4] as u128) << 32)
        | ((b[5] as u128) << 40)
        | ((b[6] as u128) << 48)
        | ((b[7] as u128) << 56)
        | ((b[8] as u128) << 64)
        | ((b[9] as u128) << 72)
        
        ;
    
    result
}

pub fn consume_uint128_11(b: &[u8]) -> u128 {
    if b.len() < 11 {
        //return Err("Not enough bytes for u64".into());
        panic!("Not enough bytes for u64");
    }
    let result = (b[0] as u128)
        | ((b[1] as u128) << 8)
        | ((b[2] as u128) << 16)
        | ((b[3] as u128) << 24)
        | ((b[4] as u128) << 32)
        | ((b[5] as u128) << 40)
        | ((b[6] as u128) << 48)
        | ((b[7] as u128) << 56)
        | ((b[8] as u128) << 64)
        | ((b[9] as u128) << 72)
        | ((b[10] as u128) << 80)
        ;
    
    result
}
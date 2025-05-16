use std::default::Default;
use crate::Error::PRNGError;
use crate::AesSubKey::{Aes128SubKey, Aes192SubKey, Aes256SubKey};

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

#[derive(Clone,Copy)]
enum AesType {
    Aes128,
    Aes192,
    Aes256,
}

fn round_nb(aes_type: AesType) -> usize {
    match aes_type {
        AesType::Aes128 => {10}
        AesType::Aes192 => {12}
        AesType::Aes256 => {14}
    }
}

fn keylen(aes_type: AesType) -> usize {
    match aes_type {
        AesType::Aes128 => {128}
        AesType::Aes192 => {192}
        AesType::Aes256 => {256}
    }
}

#[derive(Clone)]
struct State {
    state: [Vec<u8>; 16]
}

impl State {
    pub fn get_state(&self) -> &[Vec<u8>; 16] {
        &self.state
    }

    pub fn get_state_mut(&mut self) -> &mut [Vec<u8>; 16] {
        &mut self.state
    }
}

struct IoState {
    state: [u8; 16]
}

#[derive(Clone)]
enum AesKey{
    Aes128Key([u8; 16]),
    Aes192Key([u8; 24]),
    Aes256Key([u8; 32]),
}

enum AesSubKey {
    Aes128SubKey([Vec<u8>; 16]),
    Aes192SubKey([Vec<u8>; 24]),
    Aes256SubKey([Vec<u8>; 32]),
}

#[derive(Debug)]
enum Error {
    Test,
    PRNGError
}

trait CustomOperations {
    fn xor(&self, other: Self) -> Self;
    fn multiply(&self, other: Self) -> Self;
}

impl CustomOperations for Vec<u8> {
    fn xor(&self, other: Self) -> Self {
        assert_eq!(self.len(), other.len(), "Vec Xor: can only xor same length vector");
        self.iter().zip(other.iter()).map(|(&_a, &_b)| _a ^ _b).collect()
    }

    fn multiply(&self, other: Self) -> Self {
        assert_eq!(self.len(), other.len(), "Vec Multiplication: can only multiply same length vector");
        let mut r:Vec<Vec<u8>> = Default::default();
        let mut c:Vec<u8> = Default::default();
        let d = self.len();
        for i in 0..d {
            for j in i+1..d {
                r[i][j] = getrandom::u32().unwrap() as u8;
                r[j][i] = r[i][j] ^ self[i]*other[j] ^ self[j]*other[i];
            }
        }
        for i in 0..d {
            c[i] = self[i]*other[i];
            for j in 0..d {
                if j!=i {
                    c[i] ^=r[i][j]
                }
            }
        }
        c
    }
}



fn masking<const N: usize>(input: &[u8; N], nb_shares: usize) -> Result<[Vec<u8>; N], Error> {
    let mut res: [Vec<u8>; N]= array_init::array_init(|_| Vec::new());
    for i in 0..N{
            res[i] = vec![0u8; nb_shares];
            match getrandom::fill(&mut *res[i]) {
                Ok(_) => {}
                Err(_) => {return Err(PRNGError)}
            }
            res[i].push(res[i].iter().fold(0, |acc, x| acc ^ x) ^ input[i]);
            assert_eq!(res[i].iter().fold(0, |acc, x| acc ^ x),input[i], "Masking: shares do not had up to input")
    }
    Ok(res)
}


/*
fn masked_vec_multiplication(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Vec Multiplication: can only multiply same length vector");
    let mut r:Vec<Vec<u8>> = Default::default();
    let mut c:Vec<u8> = Default::default();
    let d = a.len();
    for i in 0..d {
        for j in i+1..d {
            r[i][j] = getrandom::u32().unwrap() as u8;
            r[j][i] = r[i][j] ^ a[i]*b[j] ^ a[j]*b[i];
        }
    }
    for i in 0..d {
        c[i] = a[i]*b[i];
        for j in 0..d {
            if j!=i {
                c[i] ^=r[i][j]
            }
        }
    }
    c
}

fn vec_xor(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Vec Xor: can only xor same length vector");
    a.iter().zip(b.iter()).map(|(&_a, &_b)| _a ^ _b).collect()
}
*/



fn output_from_state(state: State) -> IoState {
    let mut output = IoState {state: Default::default()};
    for i in 0..16 {
        output.state[i] = state.state[i].iter().fold(0, |acc, x| acc ^ x);
    }
    output
}

fn add_round_key(state: State, subkey: AesSubKey) -> State {
    let mut new_state: [Vec<u8>; 16] = Default::default();
    let _state = state.get_state();
    match subkey {
        Aes128SubKey(subkey_vec) => {
            for i in 0..16 {
                new_state[i] = _state[i].xor(subkey_vec[i].clone())
            }
        }
        Aes192SubKey(subkey_vec) => {
            for i in 0..24 {
                new_state[i] = _state[i].xor(subkey_vec[i].clone())
            }
        }
        Aes256SubKey(subkey_vec) => {
            for i in 0..32 {
                new_state[i] = _state[i].xor(subkey_vec[i].clone())
            }
        }
    }
    State{state: new_state}
}

fn sub_bytes(state: State) -> State {
    let mut new_state: [Vec<u8>; 16] = Default::default();
    let _state = state.get_state();
    for i in 0..16 {
        new_state[i] = s_box(_state[i].clone())
    }
    State{ state: new_state }
}

fn s_box(shares: Vec<u8>) -> Vec<u8> {
    unimplemented!()
}

fn expand_key(key: AesKey, mut previous_sub_key: AesSubKey, round: u8, aes_type: AesType, nb_shares: usize) -> Result<AesSubKey, Error> {
    assert!(round < round_nb(aes_type) as u8, "Key expansion: cannot have more than {} rounds", round_nb(aes_type));
    match aes_type {
        AesType::Aes128 => {
            expand_key_128(key, previous_sub_key, round, nb_shares)
        }
        AesType::Aes192 => {
            expand_key_192(key, previous_sub_key, round, nb_shares)
        }
        AesType::Aes256 => {
            expand_key_256(key, previous_sub_key, round, nb_shares)
        }
    }
}

fn expand_key_128(key: AesKey, previous_sub_key: AesSubKey, round: u8, nb_shares: usize) ->  Result<AesSubKey, Error> {
    let extracted_key = match key {
        AesKey::Aes128Key(key) => {key}
        _ => {Default::default()}
    };
    assert_eq!(extracted_key.len(), 16usize, "Key expansion: AES-128 keys must be 16 bytes long");
    if round == 0 {
        return Ok(Aes128SubKey(masking(&extracted_key, nb_shares)?))
    }
    if let Aes128SubKey(extracted_subkey) = previous_sub_key {
        let mut new_sub_key: [Vec<u8>; 16] = Default::default();
        for i in 0..4 {
            for j in 0..4 {
                if i == 0 {
                    new_sub_key[j] = s_box(extracted_subkey[12 + (j+1)%4].clone());
                    new_sub_key[i][0] ^= RCON[round as usize - 1]
                } else {
                    new_sub_key[4*i + j] = new_sub_key[4*(i-1) + j].clone();
                }
                new_sub_key[4*i + j] = new_sub_key[4*i + j].xor(extracted_subkey[4*i + j].clone())
            }
        }
        return Ok(Aes128SubKey(new_sub_key))
    }
    panic!("Expand key 128: No Aes128SubKey recognized!")
}

fn expand_key_192(key: AesKey, mut previous_sub_key: AesSubKey, round: u8, nb_shares: usize) -> Result<AesSubKey, Error> {
    unimplemented!()
}

fn expand_key_256(key: AesKey, mut previous_sub_key: AesSubKey, round: u8, nb_shares: usize) -> Result<AesSubKey, Error> {
    unimplemented!()
}



fn shift_rows(state: State) -> State {
    let _state = state.get_state();
    let mut new_state : [Vec<u8>; 16] = Default::default();
    for i in 0..4 {
        for j in 0..4 {
            new_state[4*i + j] = _state[4*i + (i+j)%4].clone();
        }
    }
    State{state: new_state}
}


fn mix_columns(state: State) -> State {
    let _state = state.get_state();
    let mut new_state : [Vec<u8>; 16] = Default::default();
    let d = _state.len();
    for i in 0..4 {
        for j in 0..4 {
            new_state[4*i + j] = _state[4*i + j].multiply(vec![02;d]).xor(_state[4*i + (j+1)%4].multiply(vec![03])).xor(_state[4*i + (j+2)%4].clone()).xor(_state[4*i + (j+3)%4].clone());
        }
    }
    State{ state: new_state }
}

fn cipher(input: IoState, aes_key_len: AesType, expanded_key: Vec<Vec<u8>>, nb_shares: usize) -> Result<IoState, Error>{
    let nb_round = round_nb(aes_key_len);
    assert_eq!(expanded_key.len(), 4usize * (nb_round + 1));
    let mut state = State{state: masking(&input.state, nb_shares)?};
    state = add_round_key(state, &expanded_key[0..16]);
    for _ in 1..nb_round-1 {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);
        state = add_round_key(state, &expanded_key[0..16]);
    }
    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_round_key(state, &expanded_key[0..16]);
    Ok(output_from_state(state))
}

fn main() -> Result<(), Error>{
    let input: IoState = IoState { state: [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf] };
    let state = State{state:masking(&input.state, 8)?};
    for i in 0..16 {
        println!("{:?}", state.get_state()[i]);
    }
    let output =  output_from_state(state);
    for i in 0..16 {
        println!("{}", output.state[i])
    }
    Ok(())
}

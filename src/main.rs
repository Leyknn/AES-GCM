use std::default::Default;
use crate::Error::PRNGError;
use cortex_m::singleton;

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

impl Clone for State {
    fn clone(&self) -> State {
        State { state: self.state.clone() }
    }
}
struct IoState {
    state: [u8; 16]
}


#[derive(Debug)]
enum Error {
    Test,
    PRNGError
}

fn state_from_input(input: IoState, d: usize) -> Result<State, Error> {
    let mut state = State {state: Default::default()};
    for i in 0..16{
            state.state[i] = vec![0u8; d];
            match getrandom::fill(&mut *state.state[i]) {
                Ok(_) => {}
                Err(_) => {return Err(PRNGError)}
            }
            state.state[i].push(state.state[i].iter().fold(0, |acc, x| acc ^ x) ^ input.state[i]);
            assert_eq!(state.state[i].iter().fold(0, |acc, x| acc ^ x),input.state[i], "State masking: shares do not had up to input")
    }
    Ok(state)
}

fn output_from_state(state: State) -> IoState {
    let mut output = IoState {state: Default::default()};
    for i in 0..16 {
        output.state[i] = state.state[i].iter().fold(0, |acc, x| acc ^ x);
    }
    output
}

fn add_round_key(state: State, subkey: &[Vec<u8>]) -> State {
    let mut new_state = state.clone();
    for i in 0..16 {
        for share in &mut new_state.get_state_mut()[i] {
            *share ^= subkey[i][i];
        }
    }
    new_state
}

fn sub_bytes(state: State) -> State {
    unimplemented!()
}

fn expand_key(key: Vec<u8>, mut previous_sub_key: Vec<u8>, round: u8, aes_type: AesType) -> [u8; 16] {
    assert!(round < round_nb(aes_type) as u8, "Key expansion: cannot have more than {} rounds", round_nb(aes_type));
    let mut subkey = [0; 16];
    if round < (keylen(aes_type) as u8) {
        
    }

    [0; 16]
}

fn shift_rows(state: State) -> State {
    let mut new_state = State {state : Default::default()};
    new_state.get_state_mut()[0] = state.get_state()[0].clone();
    new_state.get_state_mut()[1] = state.get_state()[5].clone();
    new_state.get_state_mut()[2] = state.get_state()[10].clone();
    new_state.get_state_mut()[3] = state.get_state()[15].clone();
    new_state.get_state_mut()[4] = state.get_state()[4].clone();
    new_state.get_state_mut()[5] = state.get_state()[9].clone();
    new_state.get_state_mut()[6] = state.get_state()[14].clone();
    new_state.get_state_mut()[7] = state.get_state()[3].clone();
    new_state.get_state_mut()[8] = state.get_state()[8].clone();
    new_state.get_state_mut()[9] = state.get_state()[13].clone();
    new_state.get_state_mut()[10] = state.get_state()[2].clone();
    new_state.get_state_mut()[11] = state.get_state()[7].clone();
    new_state.get_state_mut()[12] = state.get_state()[12].clone();
    new_state.get_state_mut()[13] = state.get_state()[1].clone();
    new_state.get_state_mut()[14] = state.get_state()[6].clone();
    new_state.get_state_mut()[15] = state.get_state()[11].clone();
    new_state
}

fn mix_columns(state: State) -> State {
    unimplemented!()
}

fn cipher(input: IoState, aes_key_len: AesType, expanded_key: Vec<Vec<u8>>, d: usize) -> Result<IoState, Error>{
    let nb_round = round_nb(aes_key_len);
    assert_eq!(expanded_key.len(), 4usize * (nb_round + 1));
    let mut state = state_from_input(input, d)?;
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

fn main() {
    let input: IoState = IoState { state: [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf] };
    let state = match state_from_input(input, 8) {
        Ok(state) => {state}
        Err(_) => {return}
    };
    for i in 0..16 {
        println!("{:?}", state.get_state()[i]);
    }
    let output =  output_from_state(state);
    for i in 0..16 {
        println!("{}", output.state[i])
    }
}

use std::default::Default;
use crate::Error::PRNGError;
use crate::AesSubKey::{Aes128SubKey, Aes192SubKey, Aes256SubKey};

const SUBBYTESB: u8 = 0x63;
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

    fn equals(&self, other:Self) -> bool {
        for (ai, bi) in self.state.iter().zip(other.state.iter()) {
            if ai != bi {
                return false
            }
        }
        true
    }

    fn display(&self, message: String) {
        println!("{}", message);
        for i in 0..4 {
            for j in 0..4 {
                print!(" {:02x?} |", self.state[4*j + i].iter().fold(0, |acc, x| acc ^ x))
            }
            println!()
        }
    }
}

struct IoState {
    state: [u8; 16]
}

impl IoState {
    fn equals(&self, other:Self) -> bool {
        for (ai, bi) in self.state.iter().zip(other.state.iter()) {
            if ai != bi {
                return false;
            }
        }
        true
    }
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
    fn xor(&self, other: &Self) -> Self;
    fn multiply(&self, other: &Self) -> Self;
    fn x_times(&self) -> Self;
}

impl CustomOperations for Vec<u8> {
    fn xor(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len(), "Vec Xor: can only xor same length vector");
        self.iter().zip(other.iter()).map(|(&_a, &_b)| _a ^ _b).collect()
    }

    fn multiply(&self, other: &Self) -> Self {
        let d = self.len();
        assert_eq!(d, other.len(), "Vec Multiplication: can only multiply same length vector");
        let mut r:Vec<Vec<u8>> = vec![vec![0;d];d];
        let mut c:Vec<u8> = vec![0;d];
        for i in 0..d {
            for j in i+1..d {
                r[i][j] = getrandom::u32().unwrap() as u8;
                r[j][i] = r[i][j] ^ self[i].multiply(&other[j]) ^ self[j].multiply(&other[i]);
            }
        }
        for i in 0..d {
            c[i] = self[i].multiply(&other[i]);
            for j in 0..d {
                if j!=i {
                    c[i] ^=r[i][j]
                }
            }
        }
        c
    }


    fn x_times(&self) -> Self {
        self.iter().map(|x| x<<1 ^ ((x>>7 & 1u8) * 0x1bu8)).collect()
    }
}

trait GF2_8_Operations {
    fn x_times(&self) -> Self;
    fn multiply(&self, other: &Self) -> Self;
    fn pow (&self, pow: u8) -> Self;
}

impl GF2_8_Operations for u8 {
    fn x_times(&self) -> Self {
        self<<1 ^ ((self>>7 & 1u8) * 0x1bu8)
    }
    fn multiply(&self, other: &Self) -> Self {
        ((other & 1) * self ) ^
            ((other>>1 & 1u8) * self.x_times()) ^
            ((other>>2 & 1u8) * self.x_times().x_times()) ^
            ((other>>3 & 1u8) * self.x_times().x_times().x_times()) ^
            ((other>>4 & 1u8) * self.x_times().x_times().x_times().x_times()) ^
            ((other>>5 & 1u8) * self.x_times().x_times().x_times().x_times().x_times()) ^
            ((other>>6 & 1u8) * self.x_times().x_times().x_times().x_times().x_times().x_times()) ^
            ((other>>7 & 1u8) * self.x_times().x_times().x_times().x_times().x_times().x_times().x_times())
    }

    fn pow (&self, pow: u8) -> Self {
        let mut res = self.clone();
        for _ in 0..pow {
            res = res.multiply(&res);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::AesKey::Aes128Key;
    use super::*;

    #[test]
    fn test_masking(){
        let input: IoState = IoState { state: [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf] };
        let state = State{state:masking(&input.state, 8).unwrap()};
        let output =  output_from_state(state);
        assert!(input.equals(output))
    }

    #[test]
    fn test_shift_rows() {
        let input = State{state: [
            vec![0x00, 0x01],vec![0x02, 0x03],vec![0x04, 0x05],vec![0x06, 0x07],
            vec![0x08, 0x09],vec![0x0a, 0x0b],vec![0x0c, 0x0d],vec![0x0e, 0x0f],
            vec![0x10, 0x11],vec![0x12, 0x13],vec![0x14, 0x15],vec![0x16, 0x17],
            vec![0x18, 0x19],vec![0x1a, 0x1b],vec![0x1c, 0x1d],vec![0x1e, 0x1f]
        ]};
        let output = State{state: [
            vec![0x00, 0x01],vec![0x0a, 0x0b],vec![0x14, 0x15],vec![0x1e, 0x1f],
            vec![0x08, 0x09],vec![0x12, 0x13],vec![0x1c, 0x1d],vec![0x06, 0x07],
            vec![0x10, 0x11],vec![0x1a, 0x1b],vec![0x04, 0x05],vec![0x0e, 0x0f],
            vec![0x18, 0x19],vec![0x02, 0x03],vec![0x0c, 0x0d],vec![0x16, 0x17]
        ]};
        assert!(output.equals(shift_rows(input)))
    }

    #[test]
    fn test_multiply() {
        assert_eq!(0x57u8.multiply(&0x13u8), 0xfeu8);
        assert_eq!(0x13u8.multiply(&0x57u8), 0xfeu8);
        let v1 = vec![0x70u8, 0x8bu8, 0x4cu8, 0x1fu8];
        let v2 = vec![0x24u8, 0x4du8, 0x69u8, 0x59u8];
        let v3 = v1.multiply(&v2);
        let n1 = v1.iter().fold(0, |acc, x| acc ^ x);
        let n2 = v2.iter().fold(0, |acc, x| acc ^ x);
        let n3 = v3.iter().fold(0, |acc, x| acc ^ x);
        let n4 = n1.multiply(&n2);
        assert_eq!(n3, n4)
    }

    #[test]
    fn test_mix_columns() {
        let input = State{state: [
            vec![0xd4],vec![0xbf],vec![0x5d],vec![0x30],
            vec![0x0],vec![0x0],vec![0x0],vec![0x0],
            vec![0x0],vec![0x0],vec![0x0],vec![0x0],
            vec![0x0],vec![0x0],vec![0x0],vec![0x0]
        ]};
        let output = mix_columns(input);
        assert_eq!(output.state[0][0], 0x04u8);
        assert_eq!(output.state[1][0], 0x66u8);
        assert_eq!(output.state[2][0], 0x81u8);
        assert_eq!(output.state[3][0], 0xe5u8);
    }

    #[test]
    fn test_refresh_masks() {
        let v1 = vec![0x00u8,0x01u8,0x02u8,0x03u8];
        let mut v2 = v1.clone();
        assert_eq!(v1, v2);
        refresh_masks(& mut v2);
        assert_ne!(v2, v1)
    }

    #[test]
    fn test_expand_key_128() {
        let key = [0x2bu8, 0x7eu8, 0x15u8, 0x16u8, 0x28u8, 0xaeu8, 0xd2u8, 0xa6u8, 0xabu8, 0xf7u8, 0x15u8, 0x88u8, 0x09u8, 0xcfu8, 0x4fu8, 0x3cu8];
        let expected_subkey2 = [0xa0u8, 0xfau8, 0xfeu8, 0x17u8, 0x88u8, 0x54u8, 0x2cu8, 0xb1u8, 0x23u8, 0xa3u8, 0x39u8, 0x39u8, 0x2au8, 0x6cu8, 0x76u8, 0x05u8];
        let _key = Aes128Key(key.clone());
        let masked_subkey1 = expand_key(&_key, &Aes128SubKey(Default::default()), 0, AesType::Aes128, 4).unwrap();
        let masked_subkey2 = expand_key(&_key, &masked_subkey1, 1, AesType::Aes128, 0).unwrap();
        if let Aes128SubKey(_subkey2) = masked_subkey2 {
            let mut subkey2: [u8;16] = Default::default();
            for i in 0..16 {
                subkey2[i] = _subkey2[i].iter().fold(0, |acc, x| acc ^ x);
            }
            assert_eq!(expected_subkey2, subkey2)
        }
    }

    #[test]
    fn test_af() {
        assert_eq!(af(0xb7), 0xa3u8)
    }

    #[test]
    fn test_exponentiation_254() {
        assert_eq!(0xa5u8, exponentiation_254(&vec![81,81,59,131]).iter().fold(0, |acc, x| acc ^ x))
        // https://tratliff.webspace.wheatoncollege.edu/2016_Fall/math202/inclass/sep21_inclass.pdf
    }

    #[test]
    fn test_aes128() {
        let key = [0x2bu8, 0x7eu8, 0x15u8, 0x16u8, 0x28u8, 0xaeu8, 0xd2u8, 0xa6u8, 0xabu8, 0xf7u8, 0x15u8, 0x88u8, 0x09u8, 0xcfu8, 0x4fu8, 0x3cu8];
        let input = [0x32u8, 0x43u8, 0xf6u8, 0xa8u8, 0x88u8, 0x5au8, 0x30u8, 0x8du8, 0x31u8, 0x31u8, 0x98u8, 0xa2u8, 0xe0u8, 0x37u8, 0x07u8, 0x34u8];
        let expected_output = [0x39u8, 0x25u8, 0x84u8, 0x1du8, 0x02u8, 0xdcu8, 0x09u8, 0xfbu8, 0xdcu8, 0x11u8, 0x85u8, 0x97u8, 0x19u8, 0x6au8, 0x0bu8, 0x32u8];
        let output = cipher(IoState { state: input }, AesType::Aes128, Aes128Key(key), 7).unwrap().state;
        assert_eq!(output, expected_output)
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

fn output_from_state(state: State) -> IoState {
    let mut output = IoState {state: Default::default()};
    for i in 0..16 {
        output.state[i] = state.state[i].iter().fold(0, |acc, x| acc ^ x);
    }
    output
}

fn add_round_key(state: State, subkey: &AesSubKey) -> State {
    let mut new_state: [Vec<u8>; 16] = Default::default();
    let _state = state.get_state();
    match subkey {
        Aes128SubKey(subkey_vec) => {
            for i in 0..16 {
                new_state[i] = _state[i].xor(&subkey_vec[i])
            }
        }
        Aes192SubKey(subkey_vec) => {
            for i in 0..24 {
                new_state[i] = _state[i].xor(&subkey_vec[i])
            }
        }
        Aes256SubKey(subkey_vec) => {
            for i in 0..32 {
                new_state[i] = _state[i].xor(&subkey_vec[i])
            }
        }
    }
    State{state: new_state}
}

fn sub_bytes(state: State) -> State {
    let mut new_state: [Vec<u8>; 16] = Default::default();
    let _state = state.get_state();
    for i in 0..16 {
        new_state[i] = s_box(&_state[i])
    }
    State{ state: new_state }
}

fn s_box(shares: &Vec<u8>) -> Vec<u8> {
    let mut res = exponentiation_254(&shares);
    for i in 0..res.len() {
        res[i] = af(res[i]);
    }
    if shares.len()-1 & 1 == 1 {
        res[0] ^= SUBBYTESB
    }
    //res[0] ^= SUBBYTESB ^ (0xffu8 * ((shares.len() & 1) as u8 ^ 1));
    res
}

fn exponentiation_254(shares:& Vec<u8>) -> Vec<u8> {
    let mut z: Vec<u8> = shares.iter().map(|x| x.pow(1)).collect();
    refresh_masks(& mut z);
    let mut y: Vec<u8> = shares.multiply(&z);
    let mut w: Vec<u8> = y.iter().map(|x| x.pow(2)).collect();
    refresh_masks(& mut w);
    y = y.multiply(&w);
    y = y.iter().map(|x| x.pow(4)).collect();
    y = y.multiply(&w);
    y.multiply(&z)
}

fn af(share: u8) -> u8 {
    let mut new_share = 0u8;
    for i in 0..8 {
        new_share ^= ((share>>i & 1) ^
            (share.rotate_right(i + 4) & 1) ^
            (share.rotate_right(i + 5) & 1) ^
            (share.rotate_right(i + 6) & 1) ^
            (share.rotate_right(i + 7) & 1)) << i;
    }
    new_share ^ SUBBYTESB
}

fn refresh_masks(shares: & mut Vec<u8>)  {
    for i in 1..shares.len() {
        let tmp = getrandom::u32().unwrap() as u8;
        shares[i] ^= tmp;
        shares[0] ^= tmp;
    }
}

fn expand_key(key: & AesKey, previous_sub_key: & AesSubKey, round: usize, aes_type: AesType, nb_shares: usize) -> Result<AesSubKey, Error> {
    assert!(round <= round_nb(aes_type), "Key expansion: cannot have more than {} rounds", round_nb(aes_type));
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

fn expand_key_128(key: & AesKey, previous_sub_key: & AesSubKey, round: usize, nb_shares: usize) ->  Result<AesSubKey, Error> {
    let extracted_key = match key {
        AesKey::Aes128Key(key) => {key}
        _ => {&Default::default()}
    };
    assert_eq!(extracted_key.len(), 16usize, "Key expansion: AES-128 keys must be 16 bytes long");
    if round == 0 {
        return Ok(Aes128SubKey(masking(&extracted_key, nb_shares)?))
    }
    if let Aes128SubKey(extracted_subkey) = previous_sub_key {
        let mut new_sub_key: [Vec<u8>; 16] = Default::default();
        for i in 0..4 { // for the 4 words of a subkey
            for j in 0..4 { // fot the 4 bytes of a word
                if i == 0 {
                    new_sub_key[j] = extracted_subkey[12 + (j+1)%4].clone();
                    new_sub_key[j] = s_box(&new_sub_key[j]);
                    if j == 0 {
                        new_sub_key[i][0] ^= RCON[round as usize - 1];
                    }
                } else {
                    new_sub_key[4*i + j] = new_sub_key[4*(i-1) + j].clone();
                }
                new_sub_key[4*i + j] = new_sub_key[4*i + j].xor(&extracted_subkey[4*i + j]);

            }

        }
        return Ok(Aes128SubKey(new_sub_key))
    }
    panic!("Expand key 128: No Aes128SubKey recognized!")
}

fn expand_key_192(key: & AesKey, previous_sub_key: & AesSubKey, round: usize, nb_shares: usize) ->  Result<AesSubKey, Error> {
    unimplemented!()
}

fn expand_key_256(key: & AesKey, previous_sub_key: & AesSubKey, round: usize, nb_shares: usize) ->  Result<AesSubKey, Error> {
    unimplemented!()
}

fn shift_rows(state: State) -> State {
    let _state = state.get_state();
    let mut new_state : [Vec<u8>; 16] = Default::default();
    for i in 0..4 {
        for j in 0..4 {
            new_state[4*j + i] = _state[4*((j+i)%4) + i].clone();
        }
    }
    State{state: new_state}
}

fn mix_columns(state: State) -> State {
    let _state = state.get_state();
    let mut new_state = _state.clone();
    for i in 0..4 {
        let tmp = _state[4*i].xor(&_state[4*i + 1]).xor(&_state[4*i + 2]).xor(&_state[4*i + 3]);
        for j in 0..4 {
            new_state[4*i + j] = new_state[4*i + j].xor(&_state[4*i + j].xor(&_state[4*i + (j+1)%4]).x_times().xor(&tmp));
        }
    }
    State{ state: new_state }
}


fn cipher(input: IoState, aes_type: AesType, key: AesKey, nb_shares: usize) -> Result<IoState, Error>{
    let nb_round = round_nb(aes_type);
    let mut subkey = expand_key(&key, &Aes128SubKey(Default::default()), 0, aes_type, nb_shares)?;
    let mut state = State{state: masking(&input.state, nb_shares)?};
    state = add_round_key(state, &subkey);
    state.display("State 0".parse().unwrap());
    for i in 1..nb_round {

        println!("\n\n---------- Round {i} ----------\n");

        subkey = expand_key(&key, &subkey, i, aes_type, nb_shares)?;
        if let Aes128SubKey(subkey_vec) = &subkey {
            println!("Subkey {i}: {:02x?}", subkey_vec.iter().map(|x| x.iter().fold(0, |acc, x| acc ^ x)).collect::<Vec<u8>>())
        }

        state = sub_bytes(state);
        state.display("Subbytes".parse().unwrap());

        state = shift_rows(state);
        state.display("ShiftRows".parse().unwrap());

        state = mix_columns(state);
        state.display("MixColumns".parse().unwrap());

        state = add_round_key(state, &subkey);
        state.display("AddRoundKey".parse().unwrap());

    }
    subkey = expand_key(&key, &subkey, nb_round, aes_type, nb_shares)?;
    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_round_key(state, &subkey);
    Ok(output_from_state(state))
}


fn main() {}

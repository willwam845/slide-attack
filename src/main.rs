use std::ops::Sub;

use rand::prelude::*;
use rand_seeder::{ Seeder, SipRng };
use bitvec::prelude::*;

const KEY_BITS: usize = 16;
const KEY_SIZE: usize = KEY_BITS / 8;
const BLOCK_BITS: usize = 8;
const BLOCK_SIZE: usize = BLOCK_BITS / 8;
const ROUNDS: u16 = 100;

const SBOX_BITS: usize = 4;
const SBOX_SIZE: usize = 1 << SBOX_BITS;
type Sbox = [u8; SBOX_SIZE];

type BlockData = BitArray<[u8; BLOCK_SIZE]>;
type KeyData = BitArray<[u8; KEY_SIZE]>;
type SubkeyData = BitArray<[u8; BLOCK_SIZE]>;

#[derive(Debug, Clone, Copy)]
struct Block(BlockData);

#[derive(Debug, Clone, Copy)]
struct Key(KeyData);

#[derive(Debug, Clone, Copy)]
struct Subkey(SubkeyData);

struct Cipher {
    sbox: Sbox,
    subkeys: Vec<Subkey>
}

impl Cipher {
    fn new(sbox: Sbox, key: Key) -> Cipher {
        let subkeys = key.split_to_keys();
        Cipher { sbox, subkeys }
    }

    fn encrypt_block(&mut self, block: Block) -> Block {
        let mut block = block;
        for round_num in 0..ROUNDS {
            block = self.encrypt_round(block, self.subkeys[(round_num as usize) % self.subkeys.len()]);
        }
        block
    }

    fn encrypt_round(&mut self, block: Block, subkey: Subkey) -> Block {
        let block = block.add_subkey(subkey);
        block.sub_bytes(self.sbox)
    }
}

impl Block {
    fn from_byte(byte: u8) -> Block {
        let mut block_data = BlockData::ZERO;
        for i in 0..8 {
            block_data.set(i as usize, (byte >> i & 1) != 0)
        }
        Block(block_data)
    }
    fn to_byte(&self) -> u8 { bits_to_byte(self.get_data().as_bitslice().iter().by_vals()) }

    fn get_data(&self) -> &BlockData { &self.0 }
    fn get_data_mut(&mut self) -> &mut BlockData { &mut self.0 }

    fn add_subkey(mut self, subkey: Subkey) -> Block {
        for (mut x1, x2) in self.get_data_mut().iter_mut().zip(subkey.get_data().iter()) {
            *x1 ^= *x2
        }
        self
    }

    fn sub_bytes(mut self, sbox: Sbox) -> Block {
        for chunk in self.get_data_mut().chunks_mut(SBOX_BITS) {
            let nibble = bits_to_byte(chunk.iter().by_vals());
            let substituted = sbox[nibble as usize];
            for i in 0..SBOX_BITS {
                chunk.set(i, (substituted >> i & 1) != 0)
            }
        }
        self
    }
}

impl Key {
    fn get_data(&self) -> &KeyData { &self.0 }
    fn get_data_mut(&mut self) -> &mut KeyData { &mut self.0 }

    fn random_key(&mut self, rng: &mut impl Rng) {
        rng.fill(self.get_data_mut().as_raw_mut_slice());
    }

    fn split_to_keys(&self) -> Vec<Subkey> {
        let mut subkeys: Vec<Subkey> = Vec::new();
        for chunk in self.get_data().chunks(BLOCK_BITS) {
            let mut subkey_data: SubkeyData = SubkeyData::ZERO;
            for (i, bit) in chunk.iter().by_vals().enumerate() {
                subkey_data.set(i, bit);
            }
            println!("subkey: {:?}", Subkey(subkey_data).to_byte());
            subkeys.push(Subkey(subkey_data));
        }
        subkeys
    }
}

impl Subkey {
    fn from_byte(byte: u8) -> Subkey {
        let mut subkey_data = SubkeyData::ZERO;
        for i in 0..8 {
            subkey_data.set(i as usize, (byte >> i & 1) != 0)
        }
        Subkey(subkey_data)
    }
    fn to_byte(&self) -> u8 { bits_to_byte(self.get_data().as_bitslice().iter().by_vals()) }

    fn get_data(&self) -> &SubkeyData { &self.0 }
    fn get_data_mut(&mut self) -> &mut SubkeyData { &mut self.0 }
}

fn bits_to_byte<I: Iterator<Item = bool>>(bits: I) -> u8 {
    bits.enumerate()
        .map(|(i, bit)| if bit { 1 << i } else { 0 })
        .sum()
}

fn generate_inverse_sbox(sbox: Sbox) -> Sbox {
    (0..SBOX_SIZE)
        .map(|i| sbox.iter().position(|&x| x == i as u8).unwrap() as u8)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

fn recover_key_combinations(pt1: Block, pt2: Block, sbox: Sbox) -> Vec<(Subkey, Subkey)> {
    let mut key_combinations = Vec::new();
    let inv_sbox: Sbox = generate_inverse_sbox(sbox);
    pt2.sub_bytes(inv_sbox);

    for k0_byte in 0..=255 {
        let k0: Subkey = Subkey::from_byte(k0_byte);
        let pt = pt1.add_subkey(k0).sub_bytes(sbox);
        let k1 = Subkey::from_byte(pt.to_byte() ^ pt2.to_byte());
        key_combinations.push((k0, k1))
    };
    key_combinations
}

fn check_key_basic(pt: Block, ct: Block, k0: Subkey, k1: Subkey, sbox: Sbox) -> bool {
    let subkeys: Vec<Subkey> = vec![k0, k1];
    let mut cip = Cipher { sbox, subkeys };
    cip.encrypt_block(pt).to_byte() != ct.to_byte()
}

fn check_slid_pair(pt1: Block, pt2: Block, ct1: Block, ct2: Block, sbox: Sbox) -> Vec<(Subkey, Subkey)> {
    let key_guesses = recover_key_combinations(pt1, pt2, sbox);
    key_guesses.into_iter()
        .filter(|(k0, k1)| {
            let ct = ct1;
            ct.add_subkey(*k0)
                .sub_bytes(sbox)
                .add_subkey(*k1)
                .sub_bytes(sbox);

            ct.to_byte() == ct2.to_byte()
                && check_key_basic(pt1, ct1, *k0, *k1, sbox)
        })
        .collect()
}

fn check_key_expensive(k0: Subkey, k1: Subkey, plaintexts: &[Block], ciphertexts: &[Block], sbox: Sbox) -> bool {
    let subkeys: Vec<Subkey> = vec![k0, k1];
    let mut cip = Cipher { sbox, subkeys };
    for (&pt, &ct) in plaintexts.iter().zip(ciphertexts).take(10) { 
        if cip.encrypt_block(pt).to_byte() != ct.to_byte() {
            return false
        }
    };
    true
}

fn attack(plaintexts: &[Block], ciphertexts: &[Block], sbox: Sbox) {
    for i in 0..plaintexts.len() {
        let pt1 = plaintexts[i];
        let ct1 = ciphertexts[i];
        for j in 0..plaintexts.len() {
            let pt2 = plaintexts[j];
            let ct2 = ciphertexts[j];
            if i != j {
                let recovered_keys = check_slid_pair(pt1, pt2, ct1, ct2, sbox);
                for (k0, k1) in recovered_keys {
                    if check_key_expensive(k0, k1, plaintexts, ciphertexts, sbox) {
                        println!("{:?} {:?}", k0.to_byte(), k1.to_byte());
                    }
                }
            }
        }
    }
}

fn main() {
    let mut rng: SipRng = Seeder::from("clubby789").into_rng();

    let mut key: Key = Key(KeyData::ZERO);
    key.random_key(&mut rng);

    let mut sbox: Sbox = core::array::from_fn(|i| i as u8);
    sbox.shuffle(&mut rng);

    let mut cip: Cipher = Cipher::new(sbox, key);
    println!("{:?}", sbox);

    let mut plaintexts: Vec<Block> = Vec::new();
    let mut ciphertexts: Vec<Block> = Vec::new();

    for _ in 0..20 {
        let plaintext: Block = Block::from_byte(rng.next_u32() as u8);
        let ciphertext = cip.encrypt_block(plaintext);
        plaintexts.push(plaintext);
        ciphertexts.push(ciphertext);
    }

    attack(&plaintexts, &ciphertexts, sbox);
    println!("{:?}", plaintexts.iter().map(|block| block.to_byte()).collect::<Vec<u8>>());
    println!("{:?}", ciphertexts.iter().map(|block| block.to_byte()).collect::<Vec<u8>>());
}

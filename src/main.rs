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

#[derive(Debug, Clone, Copy)]
struct Block(BlockData);

#[derive(Debug, Clone, Copy)]
struct Key(KeyData);
type Subkey = BlockData;

struct Cipher {
    sbox: Sbox,
    subkeys: Vec<Subkey>
}

impl Cipher {
    fn new(sbox: Sbox, key: Key) -> Cipher {
        let subkeys = key.split_to_keys();
        Cipher { sbox, subkeys }
    }

    fn encrypt_block(&mut self, block: &mut Block) {
        for round_num in 0..ROUNDS {
            self.encrypt_round(block, self.subkeys[(round_num as usize) % self.subkeys.len()]);
        }
    }

    fn encrypt_round(&mut self, block: &mut Block, subkey: Subkey) {
        self.add_subkey(block, subkey);
        self.sub_bytes(block);
    }

    fn add_subkey(&mut self, block: &mut Block, subkey: Subkey) {
        for (mut x1, x2) in block.get_data_mut().iter_mut().zip(subkey.iter()) {
            *x1 ^= *x2
        }
    }

    fn sub_bytes(&mut self, block: &mut Block) {
        for chunk in block.get_data_mut().chunks_mut(SBOX_BITS) {
            let nibble = bits_to_byte(chunk.iter().by_vals());
            let substituted = self.sbox[nibble as usize];
            for i in 0..SBOX_BITS {
                chunk.set(i as usize, (substituted >> i & 1) != 0)
            }
        }
    }
}

fn bits_to_byte<I: Iterator<Item = bool>>(bits: I) -> u8 {
    bits.enumerate()
        .map(|(i, bit)| if bit { 1 << i } else { 0 })
        .sum()
}

impl Block {
    fn from_byte(byte: u8) -> Block {
        let mut block_data = BlockData::ZERO;
        for i in 0..8 {
            block_data.set(i as usize, (byte >> i & 1) != 0)
        }
        Block(block_data)
    }

    fn get_data(&self) -> &BlockData { &self.0 }
    fn get_data_mut(&mut self) -> &mut BlockData { &mut self.0 }

    fn to_byte(&self) -> u8 {
        bits_to_byte(self.get_data().as_bitslice().iter().by_vals())
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
            let mut subkey: Subkey = Subkey::ZERO;
            for (i, bit) in chunk.iter().by_vals().enumerate() {
                subkey.set(i, bit);
            }
            subkeys.push(subkey);
        }
        subkeys
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

    for _ in 0..256 {
        let plaintext: Block = Block::from_byte(rng.next_u32() as u8);
        let mut ciphertext = plaintext.clone();
        cip.encrypt_block(&mut ciphertext);
        plaintexts.push(plaintext);
        ciphertexts.push(ciphertext);
    }

    println!("{:?}", plaintexts.iter().map(|block| block.to_byte()).collect::<Vec<u8>>());
    println!("{:?}", ciphertexts.iter().map(|block| block.to_byte()).collect::<Vec<u8>>());
}

// pub fn create_reduction_bits_array(length: u8, bits_arrays: &mut Vec<u32>) {
//     let mut static_bits: u32 = 0xFC000000;
//     let mut mov: u8 = 1;
//     let mut counter: u8 = 0;

//     for i in 0..length {
//         bits_arrays[i as usize] = static_bits | mov_bits;
//         mov_bits >>= 1;
//         counter += 1;
//         println!("{:032b}", bits_arrays[i as usize]);
//         // println!("{}", counter);
//         if counter == 26 {
//             static_bits &= !(0x02000000 << mov);
//             mov_bits |= 1 << mov;
//             mov_bits <<= 25;
//             mov += 1;
//         }
//     }
   
// }

pub fn reduction(hash: &Vec<u8>, offset: u16) -> String {
    let mut password: Vec<u8> = Vec::new();

    let j = offset / 64;
    let offset = offset % 64;
    for i in 0..7 {
        password.push(((hash[((i + j) % 32) as usize] as u16 + offset) % 64) as u8);
    }

    password.iter_mut().for_each(|x| {
        match x {
            0..=25 => *x += 65, // A-Z
            26..=51 => *x += 71, // a-z
            52..=61 => *x -= 4, // 0-9
            62 => *x = 33, // !
            63 => *x = 42, // *
            _ => panic!("Invalid character"), // should never happen
        }
    });
    return password.iter().map(|x| *x as char).collect();
}
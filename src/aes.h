#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16
#define U64(C)  C##ULL
#define GETU32(p) (*((uint32_t *)(p)))
/*
 * These two parameters control which table, 256-byte or 2KB, is
 * referenced in outer and respectively inner rounds.
 */
#define AES_COMPACT_IN_OUTER_ROUNDS

#define ROTATE(a, n) ({ register unsigned int ret;\
                        asm (                     \
                        "roll %1,%0"              \
                        : "=r"(ret)               \
                        : "I"(n), "0"(a)          \
                        : "cc");                  \
                        ret;                      \
                    })

/* This should be a hidden type, but EVP requires that the size be known */
typedef struct aes_key_st {
    uint32_t rd_key[4 * (AES_MAXNR + 1)];
    int32_t rounds;
} aes_key;


struct aes_encryptor {
    size_t encrypt_location;
    size_t decrypt_location;
    size_t pub_key_len;
    uint8_t *pub_key;
    size_t pri_key_len;
    uint8_t *pri_key;
};

static const uint64_t Te[256] = {
    U64(0xa56363c6a56363c6), U64(0x847c7cf8847c7cf8),
    U64(0x997777ee997777ee), U64(0x8d7b7bf68d7b7bf6),
    U64(0x0df2f2ff0df2f2ff), U64(0xbd6b6bd6bd6b6bd6),
    U64(0xb16f6fdeb16f6fde), U64(0x54c5c59154c5c591),
    U64(0x5030306050303060), U64(0x0301010203010102),
    U64(0xa96767cea96767ce), U64(0x7d2b2b567d2b2b56),
    U64(0x19fefee719fefee7), U64(0x62d7d7b562d7d7b5),
    U64(0xe6abab4de6abab4d), U64(0x9a7676ec9a7676ec),
    U64(0x45caca8f45caca8f), U64(0x9d82821f9d82821f),
    U64(0x40c9c98940c9c989), U64(0x877d7dfa877d7dfa),
    U64(0x15fafaef15fafaef), U64(0xeb5959b2eb5959b2),
    U64(0xc947478ec947478e), U64(0x0bf0f0fb0bf0f0fb),
    U64(0xecadad41ecadad41), U64(0x67d4d4b367d4d4b3),
    U64(0xfda2a25ffda2a25f), U64(0xeaafaf45eaafaf45),
    U64(0xbf9c9c23bf9c9c23), U64(0xf7a4a453f7a4a453),
    U64(0x967272e4967272e4), U64(0x5bc0c09b5bc0c09b),
    U64(0xc2b7b775c2b7b775), U64(0x1cfdfde11cfdfde1),
    U64(0xae93933dae93933d), U64(0x6a26264c6a26264c),
    U64(0x5a36366c5a36366c), U64(0x413f3f7e413f3f7e),
    U64(0x02f7f7f502f7f7f5), U64(0x4fcccc834fcccc83),
    U64(0x5c3434685c343468), U64(0xf4a5a551f4a5a551),
    U64(0x34e5e5d134e5e5d1), U64(0x08f1f1f908f1f1f9),
    U64(0x937171e2937171e2), U64(0x73d8d8ab73d8d8ab),
    U64(0x5331316253313162), U64(0x3f15152a3f15152a),
    U64(0x0c0404080c040408), U64(0x52c7c79552c7c795),
    U64(0x6523234665232346), U64(0x5ec3c39d5ec3c39d),
    U64(0x2818183028181830), U64(0xa1969637a1969637),
    U64(0x0f05050a0f05050a), U64(0xb59a9a2fb59a9a2f),
    U64(0x0907070e0907070e), U64(0x3612122436121224),
    U64(0x9b80801b9b80801b), U64(0x3de2e2df3de2e2df),
    U64(0x26ebebcd26ebebcd), U64(0x6927274e6927274e),
    U64(0xcdb2b27fcdb2b27f), U64(0x9f7575ea9f7575ea),
    U64(0x1b0909121b090912), U64(0x9e83831d9e83831d),
    U64(0x742c2c58742c2c58), U64(0x2e1a1a342e1a1a34),
    U64(0x2d1b1b362d1b1b36), U64(0xb26e6edcb26e6edc),
    U64(0xee5a5ab4ee5a5ab4), U64(0xfba0a05bfba0a05b),
    U64(0xf65252a4f65252a4), U64(0x4d3b3b764d3b3b76),
    U64(0x61d6d6b761d6d6b7), U64(0xceb3b37dceb3b37d),
    U64(0x7b2929527b292952), U64(0x3ee3e3dd3ee3e3dd),
    U64(0x712f2f5e712f2f5e), U64(0x9784841397848413),
    U64(0xf55353a6f55353a6), U64(0x68d1d1b968d1d1b9),
    U64(0x0000000000000000), U64(0x2cededc12cededc1),
    U64(0x6020204060202040), U64(0x1ffcfce31ffcfce3),
    U64(0xc8b1b179c8b1b179), U64(0xed5b5bb6ed5b5bb6),
    U64(0xbe6a6ad4be6a6ad4), U64(0x46cbcb8d46cbcb8d),
    U64(0xd9bebe67d9bebe67), U64(0x4b3939724b393972),
    U64(0xde4a4a94de4a4a94), U64(0xd44c4c98d44c4c98),
    U64(0xe85858b0e85858b0), U64(0x4acfcf854acfcf85),
    U64(0x6bd0d0bb6bd0d0bb), U64(0x2aefefc52aefefc5),
    U64(0xe5aaaa4fe5aaaa4f), U64(0x16fbfbed16fbfbed),
    U64(0xc5434386c5434386), U64(0xd74d4d9ad74d4d9a),
    U64(0x5533336655333366), U64(0x9485851194858511),
    U64(0xcf45458acf45458a), U64(0x10f9f9e910f9f9e9),
    U64(0x0602020406020204), U64(0x817f7ffe817f7ffe),
    U64(0xf05050a0f05050a0), U64(0x443c3c78443c3c78),
    U64(0xba9f9f25ba9f9f25), U64(0xe3a8a84be3a8a84b),
    U64(0xf35151a2f35151a2), U64(0xfea3a35dfea3a35d),
    U64(0xc0404080c0404080), U64(0x8a8f8f058a8f8f05),
    U64(0xad92923fad92923f), U64(0xbc9d9d21bc9d9d21),
    U64(0x4838387048383870), U64(0x04f5f5f104f5f5f1),
    U64(0xdfbcbc63dfbcbc63), U64(0xc1b6b677c1b6b677),
    U64(0x75dadaaf75dadaaf), U64(0x6321214263212142),
    U64(0x3010102030101020), U64(0x1affffe51affffe5),
    U64(0x0ef3f3fd0ef3f3fd), U64(0x6dd2d2bf6dd2d2bf),
    U64(0x4ccdcd814ccdcd81), U64(0x140c0c18140c0c18),
    U64(0x3513132635131326), U64(0x2fececc32fececc3),
    U64(0xe15f5fbee15f5fbe), U64(0xa2979735a2979735),
    U64(0xcc444488cc444488), U64(0x3917172e3917172e),
    U64(0x57c4c49357c4c493), U64(0xf2a7a755f2a7a755),
    U64(0x827e7efc827e7efc), U64(0x473d3d7a473d3d7a),
    U64(0xac6464c8ac6464c8), U64(0xe75d5dbae75d5dba),
    U64(0x2b1919322b191932), U64(0x957373e6957373e6),
    U64(0xa06060c0a06060c0), U64(0x9881811998818119),
    U64(0xd14f4f9ed14f4f9e), U64(0x7fdcdca37fdcdca3),
    U64(0x6622224466222244), U64(0x7e2a2a547e2a2a54),
    U64(0xab90903bab90903b), U64(0x8388880b8388880b),
    U64(0xca46468cca46468c), U64(0x29eeeec729eeeec7),
    U64(0xd3b8b86bd3b8b86b), U64(0x3c1414283c141428),
    U64(0x79dedea779dedea7), U64(0xe25e5ebce25e5ebc),
    U64(0x1d0b0b161d0b0b16), U64(0x76dbdbad76dbdbad),
    U64(0x3be0e0db3be0e0db), U64(0x5632326456323264),
    U64(0x4e3a3a744e3a3a74), U64(0x1e0a0a141e0a0a14),
    U64(0xdb494992db494992), U64(0x0a06060c0a06060c),
    U64(0x6c2424486c242448), U64(0xe45c5cb8e45c5cb8),
    U64(0x5dc2c29f5dc2c29f), U64(0x6ed3d3bd6ed3d3bd),
    U64(0xefacac43efacac43), U64(0xa66262c4a66262c4),
    U64(0xa8919139a8919139), U64(0xa4959531a4959531),
    U64(0x37e4e4d337e4e4d3), U64(0x8b7979f28b7979f2),
    U64(0x32e7e7d532e7e7d5), U64(0x43c8c88b43c8c88b),
    U64(0x5937376e5937376e), U64(0xb76d6ddab76d6dda),
    U64(0x8c8d8d018c8d8d01), U64(0x64d5d5b164d5d5b1),
    U64(0xd24e4e9cd24e4e9c), U64(0xe0a9a949e0a9a949),
    U64(0xb46c6cd8b46c6cd8), U64(0xfa5656acfa5656ac),
    U64(0x07f4f4f307f4f4f3), U64(0x25eaeacf25eaeacf),
    U64(0xaf6565caaf6565ca), U64(0x8e7a7af48e7a7af4),
    U64(0xe9aeae47e9aeae47), U64(0x1808081018080810),
    U64(0xd5baba6fd5baba6f), U64(0x887878f0887878f0),
    U64(0x6f25254a6f25254a), U64(0x722e2e5c722e2e5c),
    U64(0x241c1c38241c1c38), U64(0xf1a6a657f1a6a657),
    U64(0xc7b4b473c7b4b473), U64(0x51c6c69751c6c697),
    U64(0x23e8e8cb23e8e8cb), U64(0x7cdddda17cdddda1),
    U64(0x9c7474e89c7474e8), U64(0x211f1f3e211f1f3e),
    U64(0xdd4b4b96dd4b4b96), U64(0xdcbdbd61dcbdbd61),
    U64(0x868b8b0d868b8b0d), U64(0x858a8a0f858a8a0f),
    U64(0x907070e0907070e0), U64(0x423e3e7c423e3e7c),
    U64(0xc4b5b571c4b5b571), U64(0xaa6666ccaa6666cc),
    U64(0xd8484890d8484890), U64(0x0503030605030306),
    U64(0x01f6f6f701f6f6f7), U64(0x120e0e1c120e0e1c),
    U64(0xa36161c2a36161c2), U64(0x5f35356a5f35356a),
    U64(0xf95757aef95757ae), U64(0xd0b9b969d0b9b969),
    U64(0x9186861791868617), U64(0x58c1c19958c1c199),
    U64(0x271d1d3a271d1d3a), U64(0xb99e9e27b99e9e27),
    U64(0x38e1e1d938e1e1d9), U64(0x13f8f8eb13f8f8eb),
    U64(0xb398982bb398982b), U64(0x3311112233111122),
    U64(0xbb6969d2bb6969d2), U64(0x70d9d9a970d9d9a9),
    U64(0x898e8e07898e8e07), U64(0xa7949433a7949433),
    U64(0xb69b9b2db69b9b2d), U64(0x221e1e3c221e1e3c),
    U64(0x9287871592878715), U64(0x20e9e9c920e9e9c9),
    U64(0x49cece8749cece87), U64(0xff5555aaff5555aa),
    U64(0x7828285078282850), U64(0x7adfdfa57adfdfa5),
    U64(0x8f8c8c038f8c8c03), U64(0xf8a1a159f8a1a159),
    U64(0x8089890980898909), U64(0x170d0d1a170d0d1a),
    U64(0xdabfbf65dabfbf65), U64(0x31e6e6d731e6e6d7),
    U64(0xc6424284c6424284), U64(0xb86868d0b86868d0),
    U64(0xc3414182c3414182), U64(0xb0999929b0999929),
    U64(0x772d2d5a772d2d5a), U64(0x110f0f1e110f0f1e),
    U64(0xcbb0b07bcbb0b07b), U64(0xfc5454a8fc5454a8),
    U64(0xd6bbbb6dd6bbbb6d), U64(0x3a16162c3a16162c)
};

static const uint8_t Te4[256] = {
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U,
    0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U,
    0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU,
    0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU,
    0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U,
    0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU,
    0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U,
    0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U,
    0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U,
    0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U,
    0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU,
    0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U,
    0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U,
    0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU,
    0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U,
    0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U,
    0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
};

static const uint64_t Td[256] = {
    U64(0x50a7f45150a7f451), U64(0x5365417e5365417e),
    U64(0xc3a4171ac3a4171a), U64(0x965e273a965e273a),
    U64(0xcb6bab3bcb6bab3b), U64(0xf1459d1ff1459d1f),
    U64(0xab58faacab58faac), U64(0x9303e34b9303e34b),
    U64(0x55fa302055fa3020), U64(0xf66d76adf66d76ad),
    U64(0x9176cc889176cc88), U64(0x254c02f5254c02f5),
    U64(0xfcd7e54ffcd7e54f), U64(0xd7cb2ac5d7cb2ac5),
    U64(0x8044352680443526), U64(0x8fa362b58fa362b5),
    U64(0x495ab1de495ab1de), U64(0x671bba25671bba25),
    U64(0x980eea45980eea45), U64(0xe1c0fe5de1c0fe5d),
    U64(0x02752fc302752fc3), U64(0x12f04c8112f04c81),
    U64(0xa397468da397468d), U64(0xc6f9d36bc6f9d36b),
    U64(0xe75f8f03e75f8f03), U64(0x959c9215959c9215),
    U64(0xeb7a6dbfeb7a6dbf), U64(0xda595295da595295),
    U64(0x2d83bed42d83bed4), U64(0xd3217458d3217458),
    U64(0x2969e0492969e049), U64(0x44c8c98e44c8c98e),
    U64(0x6a89c2756a89c275), U64(0x78798ef478798ef4),
    U64(0x6b3e58996b3e5899), U64(0xdd71b927dd71b927),
    U64(0xb64fe1beb64fe1be), U64(0x17ad88f017ad88f0),
    U64(0x66ac20c966ac20c9), U64(0xb43ace7db43ace7d),
    U64(0x184adf63184adf63), U64(0x82311ae582311ae5),
    U64(0x6033519760335197), U64(0x457f5362457f5362),
    U64(0xe07764b1e07764b1), U64(0x84ae6bbb84ae6bbb),
    U64(0x1ca081fe1ca081fe), U64(0x942b08f9942b08f9),
    U64(0x5868487058684870), U64(0x19fd458f19fd458f),
    U64(0x876cde94876cde94), U64(0xb7f87b52b7f87b52),
    U64(0x23d373ab23d373ab), U64(0xe2024b72e2024b72),
    U64(0x578f1fe3578f1fe3), U64(0x2aab55662aab5566),
    U64(0x0728ebb20728ebb2), U64(0x03c2b52f03c2b52f),
    U64(0x9a7bc5869a7bc586), U64(0xa50837d3a50837d3),
    U64(0xf2872830f2872830), U64(0xb2a5bf23b2a5bf23),
    U64(0xba6a0302ba6a0302), U64(0x5c8216ed5c8216ed),
    U64(0x2b1ccf8a2b1ccf8a), U64(0x92b479a792b479a7),
    U64(0xf0f207f3f0f207f3), U64(0xa1e2694ea1e2694e),
    U64(0xcdf4da65cdf4da65), U64(0xd5be0506d5be0506),
    U64(0x1f6234d11f6234d1), U64(0x8afea6c48afea6c4),
    U64(0x9d532e349d532e34), U64(0xa055f3a2a055f3a2),
    U64(0x32e18a0532e18a05), U64(0x75ebf6a475ebf6a4),
    U64(0x39ec830b39ec830b), U64(0xaaef6040aaef6040),
    U64(0x069f715e069f715e), U64(0x51106ebd51106ebd),
    U64(0xf98a213ef98a213e), U64(0x3d06dd963d06dd96),
    U64(0xae053eddae053edd), U64(0x46bde64d46bde64d),
    U64(0xb58d5491b58d5491), U64(0x055dc471055dc471),
    U64(0x6fd406046fd40604), U64(0xff155060ff155060),
    U64(0x24fb981924fb9819), U64(0x97e9bdd697e9bdd6),
    U64(0xcc434089cc434089), U64(0x779ed967779ed967),
    U64(0xbd42e8b0bd42e8b0), U64(0x888b8907888b8907),
    U64(0x385b19e7385b19e7), U64(0xdbeec879dbeec879),
    U64(0x470a7ca1470a7ca1), U64(0xe90f427ce90f427c),
    U64(0xc91e84f8c91e84f8), U64(0x0000000000000000),
    U64(0x8386800983868009), U64(0x48ed2b3248ed2b32),
    U64(0xac70111eac70111e), U64(0x4e725a6c4e725a6c),
    U64(0xfbff0efdfbff0efd), U64(0x5638850f5638850f),
    U64(0x1ed5ae3d1ed5ae3d), U64(0x27392d3627392d36),
    U64(0x64d90f0a64d90f0a), U64(0x21a65c6821a65c68),
    U64(0xd1545b9bd1545b9b), U64(0x3a2e36243a2e3624),
    U64(0xb1670a0cb1670a0c), U64(0x0fe757930fe75793),
    U64(0xd296eeb4d296eeb4), U64(0x9e919b1b9e919b1b),
    U64(0x4fc5c0804fc5c080), U64(0xa220dc61a220dc61),
    U64(0x694b775a694b775a), U64(0x161a121c161a121c),
    U64(0x0aba93e20aba93e2), U64(0xe52aa0c0e52aa0c0),
    U64(0x43e0223c43e0223c), U64(0x1d171b121d171b12),
    U64(0x0b0d090e0b0d090e), U64(0xadc78bf2adc78bf2),
    U64(0xb9a8b62db9a8b62d), U64(0xc8a91e14c8a91e14),
    U64(0x8519f1578519f157), U64(0x4c0775af4c0775af),
    U64(0xbbdd99eebbdd99ee), U64(0xfd607fa3fd607fa3),
    U64(0x9f2601f79f2601f7), U64(0xbcf5725cbcf5725c),
    U64(0xc53b6644c53b6644), U64(0x347efb5b347efb5b),
    U64(0x7629438b7629438b), U64(0xdcc623cbdcc623cb),
    U64(0x68fcedb668fcedb6), U64(0x63f1e4b863f1e4b8),
    U64(0xcadc31d7cadc31d7), U64(0x1085634210856342),
    U64(0x4022971340229713), U64(0x2011c6842011c684),
    U64(0x7d244a857d244a85), U64(0xf83dbbd2f83dbbd2),
    U64(0x1132f9ae1132f9ae), U64(0x6da129c76da129c7),
    U64(0x4b2f9e1d4b2f9e1d), U64(0xf330b2dcf330b2dc),
    U64(0xec52860dec52860d), U64(0xd0e3c177d0e3c177),
    U64(0x6c16b32b6c16b32b), U64(0x99b970a999b970a9),
    U64(0xfa489411fa489411), U64(0x2264e9472264e947),
    U64(0xc48cfca8c48cfca8), U64(0x1a3ff0a01a3ff0a0),
    U64(0xd82c7d56d82c7d56), U64(0xef903322ef903322),
    U64(0xc74e4987c74e4987), U64(0xc1d138d9c1d138d9),
    U64(0xfea2ca8cfea2ca8c), U64(0x360bd498360bd498),
    U64(0xcf81f5a6cf81f5a6), U64(0x28de7aa528de7aa5),
    U64(0x268eb7da268eb7da), U64(0xa4bfad3fa4bfad3f),
    U64(0xe49d3a2ce49d3a2c), U64(0x0d9278500d927850),
    U64(0x9bcc5f6a9bcc5f6a), U64(0x62467e5462467e54),
    U64(0xc2138df6c2138df6), U64(0xe8b8d890e8b8d890),
    U64(0x5ef7392e5ef7392e), U64(0xf5afc382f5afc382),
    U64(0xbe805d9fbe805d9f), U64(0x7c93d0697c93d069),
    U64(0xa92dd56fa92dd56f), U64(0xb31225cfb31225cf),
    U64(0x3b99acc83b99acc8), U64(0xa77d1810a77d1810),
    U64(0x6e639ce86e639ce8), U64(0x7bbb3bdb7bbb3bdb),
    U64(0x097826cd097826cd), U64(0xf418596ef418596e),
    U64(0x01b79aec01b79aec), U64(0xa89a4f83a89a4f83),
    U64(0x656e95e6656e95e6), U64(0x7ee6ffaa7ee6ffaa),
    U64(0x08cfbc2108cfbc21), U64(0xe6e815efe6e815ef),
    U64(0xd99be7bad99be7ba), U64(0xce366f4ace366f4a),
    U64(0xd4099fead4099fea), U64(0xd67cb029d67cb029),
    U64(0xafb2a431afb2a431), U64(0x31233f2a31233f2a),
    U64(0x3094a5c63094a5c6), U64(0xc066a235c066a235),
    U64(0x37bc4e7437bc4e74), U64(0xa6ca82fca6ca82fc),
    U64(0xb0d090e0b0d090e0), U64(0x15d8a73315d8a733),
    U64(0x4a9804f14a9804f1), U64(0xf7daec41f7daec41),
    U64(0x0e50cd7f0e50cd7f), U64(0x2ff691172ff69117),
    U64(0x8dd64d768dd64d76), U64(0x4db0ef434db0ef43),
    U64(0x544daacc544daacc), U64(0xdf0496e4df0496e4),
    U64(0xe3b5d19ee3b5d19e), U64(0x1b886a4c1b886a4c),
    U64(0xb81f2cc1b81f2cc1), U64(0x7f5165467f516546),
    U64(0x04ea5e9d04ea5e9d), U64(0x5d358c015d358c01),
    U64(0x737487fa737487fa), U64(0x2e410bfb2e410bfb),
    U64(0x5a1d67b35a1d67b3), U64(0x52d2db9252d2db92),
    U64(0x335610e9335610e9), U64(0x1347d66d1347d66d),
    U64(0x8c61d79a8c61d79a), U64(0x7a0ca1377a0ca137),
    U64(0x8e14f8598e14f859), U64(0x893c13eb893c13eb),
    U64(0xee27a9ceee27a9ce), U64(0x35c961b735c961b7),
    U64(0xede51ce1ede51ce1), U64(0x3cb1477a3cb1477a),
    U64(0x59dfd29c59dfd29c), U64(0x3f73f2553f73f255),
    U64(0x79ce141879ce1418), U64(0xbf37c773bf37c773),
    U64(0xeacdf753eacdf753), U64(0x5baafd5f5baafd5f),
    U64(0x146f3ddf146f3ddf), U64(0x86db447886db4478),
    U64(0x81f3afca81f3afca), U64(0x3ec468b93ec468b9),
    U64(0x2c3424382c342438), U64(0x5f40a3c25f40a3c2),
    U64(0x72c31d1672c31d16), U64(0x0c25e2bc0c25e2bc),
    U64(0x8b493c288b493c28), U64(0x41950dff41950dff),
    U64(0x7101a8397101a839), U64(0xdeb30c08deb30c08),
    U64(0x9ce4b4d89ce4b4d8), U64(0x90c1566490c15664),
    U64(0x6184cb7b6184cb7b), U64(0x70b632d570b632d5),
    U64(0x745c6c48745c6c48), U64(0x4257b8d04257b8d0)
};
static const uint8_t Td4[256] = {
    0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U,
    0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU,
    0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U,
    0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU,
    0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU,
    0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU,
    0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U,
    0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U,
    0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U,
    0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U,
    0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU,
    0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U,
    0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU,
    0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U,
    0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U,
    0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU,
    0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU,
    0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U,
    0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U,
    0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU,
    0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U,
    0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU,
    0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U,
    0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U,
    0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U,
    0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU,
    0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU,
    0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU,
    0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U,
    0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U,
    0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U,
    0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU
};

static const uint32_t rcon[] = {
    0x00000001U, 0x00000002U, 0x00000004U, 0x00000008U,
    0x00000010U, 0x00000020U, 0x00000040U, 0x00000080U,
    0x0000001bU, 0x00000036U, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};

/*-
Te [x] = S [x].[02, 01, 01, 03, 02, 01, 01, 03];
Te0[x] = S [x].[02, 01, 01, 03];
Te1[x] = S [x].[03, 02, 01, 01];
Te2[x] = S [x].[01, 03, 02, 01];
Te3[x] = S [x].[01, 01, 03, 02];
*/
#define Te0 (uint32_t)((uint64_t*)((uint8_t*)Te+0))
#define Te1 (uint32_t)((uint64_t*)((uint8_t*)Te+3))
#define Te2 (uint32_t)((uint64_t*)((uint8_t*)Te+2))
#define Te3 (uint32_t)((uint64_t*)((uint8_t*)Te+1))
/*-
Td [x] = Si[x].[0e, 09, 0d, 0b, 0e, 09, 0d, 0b];
Td0[x] = Si[x].[0e, 09, 0d, 0b];
Td1[x] = Si[x].[0b, 0e, 09, 0d];
Td2[x] = Si[x].[0d, 0b, 0e, 09];
Td3[x] = Si[x].[09, 0d, 0b, 0e];
Td4[x] = Si[x].[01];
*/
#define Td0 (uint32_t)((uint64_t*)((uint8_t*)Td+0))
#define Td1 (uint32_t)((uint64_t*)((uint8_t*)Td+3))
#define Td2 (uint32_t)((uint64_t*)((uint8_t*)Td+2))
#define Td3 (uint32_t)((uint64_t*)((uint8_t*)Td+1))

int aes_set_encrypt_key(const unsigned char *userKey, const int bits, aes_key *key);
int aes_set_decrypt_key(const unsigned char *userKey, const int bits, aes_key *key);

void aes_encrypt(const unsigned char *in, unsigned char *out, const aes_key *key);
void aes_decrypt(const unsigned char *in, unsigned char *out, const aes_key *key);
#endif
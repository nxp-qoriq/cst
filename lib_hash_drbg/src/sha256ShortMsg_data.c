/* Copyright (c) 2015, Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* +FHDR-----------------------------------------------------------------------
 * FILE NAME :  sha256ShortMsg_data.c
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-02-04   T. Tkacik   Initial version
 * ----------------------------------------------------------------------------
 * KEYWORDS : hash, sha256, self-test
 * ----------------------------------------------------------------------------
 * PURPOSE: Test data for a SHA256 Short Message CAVP test
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#include "sha256.h"

/*
 * Original header for the CAVP test
 *
 * #  CAVS 14.3
 * #  "SHA-256 ShortMsg" information for "2891_Freescale_MDHA1"
 * #  SHA-256 tests are configured for BYTE oriented implementations
 * #  Generated on Fri Apr 12 13:47:20 2013
 *
 * [L = 32]
 */

const sha_msg_test sha_short[] = {
    {
        0,
        "00",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
        8,
        "27",
        "265fda17a34611b1533d8a281ff680dc5791b0ce0a11c25b35e11c8e75685509"
    },
    {
        16,
        "43f2",
        "39fad3d531225610ec7f9c3a2db330766058e9dd4f8507a9b6cb6479ee82426e"
    },
    {
        24,
        "d43bf5",
        "f6d58bd992614de03513584aae0a9bf6158c039b649a2d59793c6a1e1080e7ea"
    },
    {
        32,
        "4e91150e",
        "e1a755eb7a660d0e14978d0b039890258c8fbf5a4e48bc562c30431278497f90"
    },
    {

        40,
        "813bae6057",
        "6f490dbd7e09ebf18a38d93f9f5e816f3da3fd37a261880bcc2e77d644b212de"
    },
    {

        48,
        "1381db0b2b6d",
        "e8ee7fed3eadcfb023f7c19bc6c32fbccbcc2085e2f6c8f83d4c4ea1b81ae030"
    },
    {

        56,
        "5546fa35ad3774",
        "23514cd9693849222527afe6057bcf1a8725cf7dde6201bb73153012c1cb4deb"
    },
    {

        64,
        "ec2710b905ff6661",
        "bf34790e951e1a30697710f4459f696d7f36245998ff3c949ac254223af717a1"
    },
    {

        72,
        "4a14d6e2b48b8f992b",
        "de93eefac2e21c98c218c0a4faf896405da0d8775ce2cca0722b9602e3d39d07"
    },
    {

        80,
        "20d0a430685a268edf83",
        "0b75ffd148a78980d31dd4f98ac063898287c03576158a1d60ff47f191e76f8a"
    },
    {

        88,
        "f5205505bd2e3a6a91e9a5",
        "04b688e9891d9143a083bb73599833084572ade6ea4841e5a0e82eb02d1fa6aa"
    },
    {

        96,
        "a082ed65038b7a0d60b28e6f",
        "7b2a5b4b8850e1a55c2bfc4132d5e28c9b0ac4cc75d4c4beca8d7525a68aaff2"
    },
    {

        104,
        "dea156e7151bc3500fce107a98",
        "1dc015c7b78a954a6ca7a4ca8d6355a2ec4acfd06c723f546d1a73b0ff0bf284"
    },
    {

        112,
        "50c0273fbed6029449d65bb98a47",
        "3c419d340f9837a313b59dc36a6ead1644e8d42a82b523f82c3485354eaf0ed8",
    },
    {

        120,
        "6b7e9f1a4177872fdb5b018e94ec5a",
        "2b4daa40674c9d83e9a91e6d7bc02ead0e8664a02af75248149dae725dfda6df"
    },
    {

        128,
        "0ecbb2184a79cd9a82cf0a63ec825e5e",
        "5d8b8113618132691b549c91cb62139431c6600483151d1a49f7f65233bd917c"
    },
    {

        136,
        "f585e38e6ca2418f4e872d3d3a2956d092",
        "3ca17e3bd2121c1ed5a2a452992eb07ddf5f1a86f500625429aca2e95300cd85"
    },
    {

        144,
        "4b1f5800c52b06bc789f4c4ce446d383212b",
        "39f39d3eaabdfdaa629d8daaa053744f60e669bb90fa461bd00f38ce3c27ca0c"
    },
    {

        152,
        "087281dedf83d1aa89998eb6d69a15bf24b7e6",
        "e796f5a3b22ca3ccfb0ee49ecac53804af76a7061d06acb6e2fb778eafb58887"
    },
    {

        160,
        "4266d13d616cda1542ceddcc1e776eb4cf65e0e8",
        "f39057a2cc50dc47b0aadb79ef147c334f3fc584d487538a6134c6f87f7771ae"
    },
    {

        168,
        "67eb4b12f6d02142989ceb96ba11330bbe20f92859",
        "11ee5eeaff4dab5ad30b40a1204a3e73a6dab1a0048c3d00ee67134f6ed2d61f"
    },
    {

        176,
        "c0c059b3609ad94b963d62973de4d447575d57375d0c",
        "4549d0521fccd9d8dbbfe2f99639aa3c9570e8d35921366805d44f95c630d3dc"
    },
    {

        184,
        "79bb069f58d0e9d0799181b40392e4a045f772fd5789a3",
        "710ee5f3a226bb295338f11973d8282725a90a228fe03d8215d946eb48836276"
    },
    {

        192,
        "fe6fb48eb317a3453bb75aa2e7accb94760bce6d88402c9e",
        "17d206aa582e07c976b8c48479e2ab27e99416cdf2923f6710d8f44e3995768f"
    },
    {

        200,
        "c5a2dbb6c429fb7472ad0bb1ad61fee8182eace06eb3c7d116",
        "d4d7c14bb5de0ca1f0d43556b0bd7f92a33b4c517992c1c16fa81e1e4a784893"
    },
    {

        208,
        "28a07ec052c75d6eafc07b33458ea732fe7fbf604d4a77361459",
        "c817d82b6b934988a0a89281765a56e5e05cd239265e9c6bbc8f644be32fda10"
    },
    {

        216,
        "18bf11fc8c192885c04e58ccab89ee73b6a1352c1feef8299c5c42",
        "ed41ed627a4d15ce38996b5cc84382d0a60ba68ab48e914c66768d51424d5653"
    },
    {

        224,
        "89ec9b79d5cbf7bb422a2e58e31a2080baece7aee397b12d0f5bcfda",
        "345a18c267f998b37d47bab1c8d15172293733077b9b46d021ef6ad44761b354"
    },
    {

        232,
        "57137111b33c85673d39fef8daadf83bb86230d182a4cf0ad6e883abf8",
        "20c58f0cd56482a737275bf92610596fade4ac3758e0c7635155172c73bc9cc3"
    },
    {

        240,
        "00034788ca5e4599b29af791e208f8ecf3a9d75106f0c77210c8973475d9",
        "120cbc1c10b590ea1e387c499d82422e708bac5a1b2234b3850ec19576355de3"
    },
    {

        248,
        "89eaa73fc05679cd45754c02da57030699fdac7b2abc580239e22900279cac",
        "39b722e2db6ea35c7cdb7eff78bd95136d8b0932525278f8d8c7bf8b8e49d41b"
    },
    {

        256,
        "4853e01ee579b413f5c2b2caf975975eb61862204334088260586a340960848c",
        "945b6b24eaea5dbd34bc9b227741ca0a232992826ec60359976211858c8eddee"
    },
    {

        264,
        "aa97223ab72698b3006d9f4b6ebf0c171102013fc0bdb5b2007373182830e609"
        "c2",
        "12f07ac8450974fbbdca511e1f28c8fdf61d24924adc1f5aac51a8a5b87e808d"
    },
    {

        272,
        "2ee0adcb50d7eed60285db6b72eeb8cda19c36fa6a94963bc08a11f9375178d2"
        "c595",
        "d185306c4e40a5463c20ea38750da1290d2c002edab2d6a40b0fc0bed9c3da7d"
    },
    {

        280,
        "a0a0d602c1ada01384c47971f515df6faa27525e417767530a62182b00445ecd"
        "fee202",
        "b837391a7d8bbb0eb3088a4c278873d3c62e9e0f21ebce42aa380e870571e4fc"
    },
    {

        288,
        "83c4ba5cd579d1b2461384565d044b77df149d3aaab3faafe18d2f044960d6f8"
        "f30a1c93",
        "3f496d8aef819ff64eeec702bcbc6e82c8d6978197bf01e1379efa1155d5b07f"
    },
    {

        296,
        "896a2a32f1246a69a53ad17501e7c3faa69df6a128ebcc1c07a4e064e13ede45"
        "e578991d8b",
        "c2a7828cc9bb541ee7e386f082d953001827075a86c00c401e8ed15e4095708b"
    },
    {

        304,
        "4052bb56f3048884e6f0af8aa38e9db29b96f0ac0d5e81832963a2d07625a42e"
        "71399ded7799",
        "013fbfc14af05ba0d87a43f536340cf7269544ca31b60dfd1be269cefa940f00"
    },
    {

        312,
        "593be2b3e49b04c86ed9f539991f059deaf473cd280eec5405674f200193b37e"
        "8a50ab45685fc9",
        "fe108cde934cc6b45741b20f5c9fcbedca72a3358fdafcad21c2f19b5f38e582"
    },
    {

        320,
        "f238e8bf35ce3fa9e6b00368cecb760070ec463df6df19f76ad96995291392d0"
        "95b829ba0b0190fe",
        "b6e8870dd685bbf586f1d26473e39e5f0c16988db36240b4a75c20a0efbad067"
    },
    {

        328,
        "a749342b9030d68021169e01539cf484786053ab7c2ca9b76a6d019d31e75f5c"
        "a9a8eb8dd13a523c5b",
        "aaace8ccb0e77d5ed0d508391767ce1033bf079ac2abba0e05ba0e07e4dc1fb3"
    },
    {

        336,
        "29bc6e4a4d32a60b0d2864398fbc9712e9409a9ae1ed14eaf6d51dcba51aa283"
        "e55e0aeff47a19d25573",
        "06b8dd96bb28747047aeb47fb591b440a352ccd2d799552a8c80479411ab03c7"
    },
    {

        344,
        "92c2179fe238cc7a9f57a684f532bd8465d63c0b0a7dc24921040824c89fc38c"
        "06cccc080c857e95baba5f",
        "5e0f4fb033c08746d1c54ba7f66c2f2edbf23b4dff67c94eeb3286c4d503a567"
    },
    {

        352,
        "1478027554c44096a10b1c2aadca74a6ee3006e4a01a8dbd09422cd900b310c6"
        "b08152489ab61af0d98f0af0",
        "d28fec309d3c794c1d0147fd48e0d8f14ca3ff86f0084dc634defc6cd008dbba"
    },
    {

        360,
        "e2379e297637a72c4f4108c87cf9665fe37aff86d999e066f06d5862100facfb"
        "ca9e0cf0e886c6a94902bad5ec",
        "125c63acddafb2e982c85b715bfdd0dafabca16029161dc4f18edf8cee9c8200"
    },
    {

        368,
        "acd995057abd413d5cb5bce171b735357cc7b3f3dc19a992be76cac791e01e4d"
        "ba7956e289a15d926c5f2f376302",
        "bb173e0e96f9137aac9451cadc0e0759578dcfdda0bddb4b59e48a35733c859c"
    },
    {

        376,
        "76fefd2f3d97a90080e3c3feedab7dd97dd3bb3a4ae08162a0b7ac0e56a7e19d"
        "5faac4749ce86aa2f47d10c0a77c0d",
        "65412153a70fe7949932c8b9672d6e7be57990965120e04db2e63f336c65a645"
    },
    {

        384,
        "52a5e6235ffd9c05ea0aad6c273f8f85df4ff8bf1443a080e8c94816bbcffbf0"
        "9450940ec26e80b6c3c2c56964f04315",
        "e39207b8f451e153f491c634e1830336a2e5085b47b10962495dd4c939842b4f"
    },
    {

        392,
        "44eaf6cc8fe7aaefa94e940fe9ebe2f7ff82d923850f0f25d752da47258b0872"
        "c683d04ecfcb09abe5489a204ff032f14f",
        "fef7a86b380ec6077a66594d307e57f1cf4bf1fc8d9a5fb2209f8c419434be2a"
    },
    {

        400,
        "b19c3a310ab5bf72175e99a38166ecaca196e84a4d3a41b5f2dedf80e356d6c0"
        "f10198703c4e6a14497e149d54acdd8de70b",
        "923a3d57eacb00a460b90f14b404a06e419faa85391123774d8709f9230e3aa7"
    },
    {

        408,
        "294d59bd2b82478944fbd053f11176ebd3b3fd4d026667c8a3892360bdde8270"
        "48466a9487cc4ec598e55dc64af6fac02e176d",
        "49a7f28226a0424db76d21e31dd55a4c26baa23aa627330c9f4b5d4768aa7dc8"
    },
    {

        416,
        "6de7cf45c645aef2197eb125131794b10d931e5791e9bcde1935696519aed0f9"
        "40d8b563fbfb91433cd37c6379895045f7e20cfe",
        "aa3a2c99f883cdfdec0c4670d36f2ba459a97f1950c6f3067dbfd0346ec2b8a5"
    },
    {

        424,
        "b8134e28abde428fefe6ec8d443c285c8897e3092bf62d30e3879007a1c8a09d"
        "c3ecd4648b8094eed04e93f4f3825f9c150b37fb87",
        "7c353fd4df8c702be65cfd8d5f3af49c0c07c0f83aded98ce1f77d63d7b65669"
    },
    {

        432,
        "5330ea34a16c04c597d4353869158644892e0d77d6d3bfc2110f8638902e9413"
        "36daf6f8a2846c7ca70678e6fc86b536359d6a67f2b8",
        "02609c8f7538dbb522c471854b46985be75e698f10bd369d09d052071b7ac535"
    },
    {

        440,
        "9265699847b75d392802ef66384fd68b828a1b1affd91f7fb92cdf55311477da"
        "fed8e5a0b8c6108614c709e750369011d2f2daf90cb291",
        "d668b08fd3335ebf828466e296edfe798cd0aac444ea6b5bc20f50e3e54bf46f"
    },
    {

        448,
        "46107333aad1ab62dd3aa9f99f9ad2df1024e1ec729dd243315800e220648a77"
        "0604fa75595f296849795d860162b58629aec7b5af248746",
        "5c37096b453119f99c8b6a0adeffeb4c96629f679bd7042c141a742a9e71c476"
    },
    {

        456,
        "072934718fe82f132cc7b55c055eccc40300496036934e58759e129b45a4e0d1"
        "fdb16392273220d5280944ab24e1a02d1cbff2b259da66460e",
        "f7b108f888fe703ac2069ff2f03b3d05c7be1500a4469c1305fffd0b81eef8cf"
    },
    {

        464,
        "cceb97a4bd65851115c08dedeb442ad3389bb2d8958337d346c6abfc786c48b9"
        "c72f2fb4032f503134e7899fdb60126c7ba4181e5876a8a07f40",
        "f1101e12511e8082c3e68a0175cd295fe690fdbb633be4850e32cc6e7cda1e05"
    },
    {

        472,
        "0c884b0d96bf65c2af0715583ac5fd7d7453de7bd852a3234042a1034c501de0"
        "076e0e60c8a9250657b70b6351d0ea8bcec02ec740398d899f6d44",
        "154f359f0271a2be571ea57daaab1a35e60afb6b81a081f88cbec01185438793"
    },
    {

        480,
        "c1a905e5daedce13fbd0979dee7e3417ca48fa922ee1256ec7ce777018182214"
        "7a44e8256184818ae22f3d63726fea55f13af821e783db7c0db1b11b",
        "7d4e543be0af202d3a8ac4cac1594c5ab247e3ecf32b8a96bf0d4a324bc5c944"
    },
    {

        488,
        "3786d3ed8f030c74a4077808a5146254db60fa5e8b2855721e46b65b7f060cda"
        "c536bb50127c9fbebaed4eefa8da9ef4feed68d1fc758b7623ff33f19a",
        "8f7ddc721e769d27427e89b81913fc5be1cbaf11594b239706fa34de17ac2b46"
    },
    {

        496,
        "5b1fa882c10cc1d1476345f02b397d531e4bc92d9afa929075947fd6b7d5ec41"
        "a9ae98de2e449daf563ca60831365c3ae197216ff38c01d5f04ce5ff2e9d",
        "0c6c8ef29c951ade7b24f0d6f0e2bfaba398af6b6b8f9bccba1eb8da85e11d16"
    },
    {

        504,
        "bf06f8bfc9fc1992e909ea7774ff856d778780084a651cce68febfe07d17a5dd"
        "c1dfd20385304b970b1285879b811e4fd370cb193f0d92282a473976b38dfe",
        "8b2bdb7533ac8449e98f48caee89eae8456b22f620c2cbf78b39d0f41fcb51e2"
    },
    {

        512,
        "9715a6432a2d2b8c0b9ee5800e386e1dca8637e44db1d8de0fa2a4dd25678104"
        "b7d8f789b47a86bac4a33d3e7fdf889edc934a04ece02b42c8ca3415c89a99ab",
        "ce773bd28ef867bdfcf397239ef5c6947191b957b433669c19262c356d267aa1"
    }
};

const int sha_short_count = sizeof ( sha_short ) / sizeof( sha_short[0] );

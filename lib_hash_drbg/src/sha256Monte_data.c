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
 * FILE NAME :  sha256Monte_data.c
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
 * PURPOSE: Test data for a SHA256 Mont Carlo CAVP test
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
 * #  "SHA-256 Monte" information for "2891_Freescale_MDHA1"
 * #  SHA-256 tests are configured for BYTE oriented implementations
 * #  Generated on Fri Apr 12 13:47:20 2013
 *
 * [L = 32]
 */


/*
 * The hex string used as a seed to start the monte carlo test
 */
const char* sha_monte_seed = "8467c77d0cbc44d3dd0f3c5c3180ded8dc66b4f6dd94d9bc33dc6628f2d22d18";

/*
 * After every 1000 iterations, compare the resulting message digest with a value below
 *  There are 100 values to check
 */
const char* sha_monte[] = {
    "944e271a60922d7da2a6d96a957a070a0f42ba3363e6338c82933de175db0dfa",
    "db146bd65ee17291f7d55b38b18de99e6d29f02367a49d045637470633f74851",
    "a1df7a07eac023302f0ad00e951cb02344ab342d45d996986677e701592122e0",
    "ddfd572af0fb6b1818a8dde86bd4724299377631996c9c6607d0618330384b04",
    "e83d17f170d9202ef629e01eb818fefe3acb64bef3933c7e1f021fe3cdf27533",
    "c8ffeec1ba4bc28efce6c18c8e4fdc8c388b72a2efd19bbaa1f701117e85aed6",
    "b127ca59d99dd055a98db67686facf25f04e0fe01f56f6dc305bf427c44b24fb",
    "fa018e79c22c7c3969f129121069464997a0de17f0d4181762bb72a1eb8efaed",
    "a9ca64f22233fdd42e7a3b4fe2de98b6d2dc3b6ace25a907a655a7bbc1f32263",
    "6d2a492872270ec73d655a382aaa8066cfb4424205ef3f49792c27ed94fc0d43",
    "a55e8c24f819c6208dbbf63b550fb199d25f805f56aff14ee705f974d4240fe7",
    "bdcc0bcc4b77085c01e136179934f2aa64547198e79d64050251be91d29a53a0",
    "0c0b6ca3aa13076ca73c94b13e56de8cd4ad7f2aee65ec23409fd6552122aa52",
    "a7baf8525759831f7af94daab272709945a7a10493f013baad8b76a87396c7be",
    "bf2f341966eeba190a2db34452287b6e999ba7e83d4e8c66a6f879c20544bec0",
    "c48339d6e9aa1e0ad01afeddf99c014759f0fbc8a3de417908011d37979d4b35",
    "4c2738f0a9d7ec934a798b187d0f23540bf2268973cb5bf641efe5b7a9438a6e",
    "6b4c14a02aec454923837658a93b9e50f129732915eb8b024338141dd49daf9b",
    "5409d86a64fb33bc5494368a9c61562064dbd79bf6b45d5071412c17783371f7",
    "dfaac7cccf2eb5a1cda0302e49402219113852d0b07fbea8d74a1814172ff0ca",
    "f97db10fd31c383ff299323ea36217dd7414f61b3abdf0bc19d7396a77c55036",
    "b5b8bec3c99f0ccd6d008fa49322e76f9306d135e49b15dd1cd72a8249598c63",
    "4e1ebebde99332809b588b766effff2dd86dd2ca7cfe4e76dd6792125df76378",
    "d1960cd65b06966858d7d08816975f9cb630dace927f4c5e5cb1bc315c98e072",
    "29da315861faa443f078e9c1e7e7e3aa3c1eadff620fb2dfdd0f57fc8bcebd76",
    "ee4872cd6f60d96564ace4e31af03a72d565a879e4ea97d066fcd2aa044452f0",
    "623f42ebb7b9fd220b886e13ca158bfac37960b77e3e057d354d928586e15370",
    "a29a96448008b7e6c9d88e09252fa11561ca37c83f11acf703b99871a5eca474",
    "bcbeac58bf466fc26ffe9339d0e5961d8b413c3234581ec31a2f545ddd52b614",
    "2e096bd69fa0fde09fbbae82c46e72b6b8f93c13b6d91cac746fd3d7993f5e27",
    "cba50d227515bf246839b005aa15759f4e3157a99c47c1b227d4fb36e4c6fa83",
    "0624d6aa25d28c1b1bc039efeca07356107f2427b4306edf5e4552505c0c855e",
    "e5e1a6504977ccf002a9749997764ee16326f5b2b6f36ad516995a432974630b",
    "f488ff9101fc19c08cd38c2efc90d20361015bbb4f2f5ca9a31d695294ec63b9",
    "c812b89aded0c227b66d58d7cd7b830bbfb7a3edb106cbb3a6ca9812184b73af",
    "eec9ac37bb817b2b868ff90787a63acf8e872b293eaf2c843fc393bd25c4f1cf",
    "6565eb8ca62c88cffa86f6177403fae48f22bede979569c42011296974304bd9",
    "5ca86066d5b5afbfc04b9e04f820495eff622fabc9f36192160f033558e2398b",
    "0161602b56f46e1054c48f20aeb4b015ca1af2cd982963c932812527ed4bb45e",
    "33bf17af952ba75c633673174d214088ecb3ece88656ee9138f00e68f8c807c1",
    "23545b89febf74baa1028d3c41b711f403c88889ca00a7d929f1c2b2ced21515",
    "2a50f815e443150d7cde0cfae88ce30d7036a6fb50d8d796e42df6e3fbc3c559",
    "d13e24451d6b18e1d657f01c7c0c758959397b52292b6bb6a193d48243095f49",
    "ceed26ff3737e0883e5be3c3850cfd55f775b4ce1dae60d1deaed1fdeb3697ad",
    "81d8ec91045e167fa6f2dc34d13e97dae44ee3ed241bc574070b03add8c09241",
    "288fccccaea3777b546293d9c40332e6f9cc2487f1e1bd514976586475387372",
    "3c133c36863f2387d59b94135ed90a0b6c86c769dee3347cadefc5fc8078da89",
    "93e57b90dc3519d00bf57c67c34ae45951287b4ba76ef7a005d66c49cb5430ab",
    "d60226c89541b00794bf87b557e369976ad3f71c8ef12a0e9f381a7fc31e325f",
    "c95645915b47e63065f039527314992a3092751bf79b4db9c10a9a5fdb3377f6",
    "4232212454dcbc51f32f3cf9b1a8a47a904f81e72a5313bb90f06ddd980d8ecc",
    "a22271a1d1cf7e61876dc8265664dad2511e86e01c0371cfe5e4817f51539ebf",
    "0fa015dcae3e551d26dee994256fef85e251aa88cca2598a43afce805794b1c7",
    "4fa6660b3771f1a66c7bad1c10d485ee1639a824d6b44fdcbcd7c5c47e8addeb",
    "16a91ac1764faeecfaec3b01ad7076cb1781cc9aaa7e8818c3f6ea7ab2a7ed87",
    "0a49e3b4c75b5960a55ff17ccbb1bf45b2facd3c492080aff35651a21a8537a5",
    "f9482c9f46504373743aa93d27483c0b92aa859a132dcf8e78babe43630660b4",
    "6132759422ef9d493c20b80f3bb25fe61bdb4e17f6f4f9b067e09b8ad2ced64f",
    "d7c513f2fb39c0185a5c70bab8d81ae44fffe22623af2f45aadd4c05a9c3ce3b",
    "6d5028c9c1c8a37721457f8e9a9bf8469aacaee628facd36464edf412572596c",
    "e88373ea3af2c339875737c276bee794bf02d76af5afeda22db87859dd136ff1",
    "94628bd09e58ba6dcf0771f9334803e5c242cc50c3acf654376ad9bdd7b5a3f0",
    "a00ff6b9953558872be51930bf9e67024d88722fc1c85994d14f5403ac957a67",
    "72065798f4dd4bb2e361bd548893dca16e0708fb5d459b805b3b6a94e65186d3",
    "2585c1597c8b5ff220c37d303341e74dfef4da81f16e5b7dbab49b301c4df726",
    "5345f2534717d54d73758df54b63683ba67b869038c0c753e213b9b5d5890efe",
    "fd8d7d12b6a4aadd9e8d48656259b491499081dadfa9c5bb954874c18f2cec72",
    "08fb9451a38f278fc8559643d7be2d55892ee4f78c0410141f02155d753dd82e",
    "fcffd74d9835709e7357ecfb7c3dd905645e46114f018d3c1b1a17a1cf5d052b",
    "b9054621a7b8d4da7449a8aab731f674f1580d72c19a5d09c87ac1050cd321ef",
    "1d92f72eb9d4f50766e19607a80fab7126ae0c241e319d783c09b2e99bca6a20",
    "7a218883d3ee9393c9e78b8538364921cfa2fc0d7528793c997be953eb4caa12",
    "00e133a8a881f166a2e9bca14e9bfb3bcf32b56d38e3cdcee1823728853dbedd",
    "74f36232d0afe4fe6f1a7baeae26aa31f40383c935b0da5514da16948cadbb21",
    "104d075d3462f7d4753fede7ce07c6fc2470366f39ec62862c847cb7545b57bf",
    "6f3947cd15012cd6db485ec4b03eebed4aa6b4b0c26d1331be2010c7a65b0aad",
    "c54c4d03ea6c4d2d0e99b350ecc7510cf73c005fc51e43e91f0e498d54e5c438",
    "1f5fb958803be10bddcf0916fcdbd861fab7460c02cb5caf25345416ac619e02",
    "2e8ab1cf7e74c1361fa8b9d7a7bf1e34ff1f3ff34d48f3ff61b0419be24b9c86",
    "d57d80e80dcdef8c68ab2333a5db0c7987d4e80df296482a61f39a23d35d6560",
    "0c5082f4d669cd03c7bcaead186e20f8c545012a2ac5b3cf14623a64ab55d7a2",
    "7f94122142ecb61585b4916a2d641f064d9b912cc2c4c7a498d03f92d2622de9",
    "e19715677b1376222cb6a2f0959aad6e85926397e4356a369a5cff9f19f101f7",
    "da47be5e712048436166f7541df3d0fa7a9c5c772e1c78412043b4f348aa74ed",
    "af9880fe92b78edb5f0eb7e45a2e994d29be66da66127af42d796354def7c508",
    "c05b6d784836e2b6e41328c60f1e21525144b3fe8c7ac2975541242ef925b1c3",
    "3df06c5cac88d6509dcc06dc4dd79d4460242cecc1c45a61165ba06b7e845852",
    "78ce5c4c87a5ab47693f68d8ee0fc1a86723b03dd4961cf62fa9f22383515301",
    "6b8ac5af86ff3cf0a8fa46319dcb74f1626395a27420314629f429a284719204",
    "a5b576e6dc3aeb5b8bfdf7de38555e5f57915365e2dea9b995fc70ad3fc2086d",
    "5936b2326fb4bb58d4fa12872955291f5371dfa11bd273fb5635d546b2df0d7d",
    "98e478549cd05cb380fd7b570109b9cec274fdda9af400194417a9d04464aa74",
    "ac406b7a06fc2201e33fa2be289bece96e3096331148542601382be2bf77f93b",
    "74372c1bfc3bfa5875da0fce5d6230290acaad89a3265bbd09f15829c95e036b",
    "b96bbd83c90a9e24d81ccb3af3eaddac310523602ec2741000f457daea9b2a8c",
    "54f8fed5b28fdae144bb9d6e2e34d9e78d18bce17ac6ba423aa08c032741931f",
    "68231efa3f1ab3d2ff36d31a2a625885f8cf265df392cbe08e9b9d337fbc4be9",
    "eee657d238451820061c60747cd4877bdb10d3a85abb71ed1dc97b9e1d8083ff",
    "25669f9e377f6fce30ba1145aedef6fb6c34b650a1b420308053468b4ab1882c",
    "a8bae75a9a1125bc99ca3c3cbec5dea8f24665b9fd836b8032516da462eb8f3f",
};

const int sha_monte_count = sizeof(sha_monte)/sizeof(sha_monte[0]);



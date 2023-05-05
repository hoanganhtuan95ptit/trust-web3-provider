// Copyright © 2017-2022 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

"use strict";

import RPCServer from "./rpc";
import ProviderRpcError from "./error";
import Utils from "./utils";
import IdMapping from "./id_mapping";
import isUtf8 from "isutf8";
import { TypedDataUtils, SignTypedDataVersion } from "@metamask/eth-sig-util";
import BaseProvider from "./base_provider";

class TrustWeb3Provider extends BaseProvider {
  constructor(config) {
    super(config);
    this.setConfig(config);

    this.providerNetwork = "ethereum";
    this.idMapping = new IdMapping();
    this.callbacks = new Map();
    this.wrapResults = new Map();

    this.emitConnect(this.chainId);
  }

  setAddress(address) {
    const lowerAddress = (address || "").toLowerCase();
    this.address = lowerAddress;
    this.ready = !!address;
    try {
      for (var i = 0; i < window.frames.length; i++) {
        const frame = window.frames[i];
        if (frame.ethereum && frame.ethereum.isTrust) {
          frame.ethereum.address = lowerAddress;
          frame.ethereum.ready = !!address;
        }
      }
    } catch (error) {
      console.log(error);
    }
  }

  setConfig(config) {

    if (config.ethereum != undefined && config.ethereum.address != undefined) {
      this.setAddress(config.ethereum.address);
    }

    this.networkVersion = "" + config.ethereum.chainId;
    this.chainId = "0x" + (config.ethereum.chainId || 1).toString(16);
    this.rpc = new RPCServer(config.ethereum.rpcUrl);
    this.isDebug = config.isDebug;
  }

  request(payload) {
    // this points to window in methods like web3.eth.getAccounts()
    var that = this;
    if (!(this instanceof TrustWeb3Provider)) {
      that = window.ethereum;
    }
    return that._request(payload, false);
  }

  /**
   * @deprecated Listen to "connect" event instead.
   */
  isConnected() {
    return true;
  }

  /**
   * @deprecated Use request({method: "eth_requestAccounts"}) instead.
   */
  enable() {
    console.log(
      "enable() is deprecated, please use window.ethereum.request({method: 'eth_requestAccounts'}) instead."
    );
    return this.request({ method: "eth_requestAccounts", params: [] });
  }

  /**
   * @deprecated Use request() method instead.
   */
  send(payload) {
    if (this.isDebug) {
      console.log(`==> send payload ${JSON.stringify(payload)}`);
    }
    let response = { jsonrpc: "2.0", id: payload.id };
    switch (payload.method) {
      case "eth_accounts":
        response.result = this.eth_accounts();
        break;
      case "eth_coinbase":
        response.result = this.eth_coinbase();
        break;
      case "net_version":
        response.result = this.net_version();
        break;
      case "eth_chainId":
        response.result = this.eth_chainId();
        break;
      default:
        throw new ProviderRpcError(
          4200,
          `Trust does not support calling ${payload.method} synchronously without a callback. Please provide a callback parameter to call ${payload.method} asynchronously.`
        );
    }
    return response;
  }

  /**
   * @deprecated Use request() method instead.
   */
  sendAsync(payload, callback) {
    console.log(
      "sendAsync(data, callback) is deprecated, please use window.ethereum.request(data) instead."
    );
    // this points to window in methods like web3.eth.getAccounts()
    var that = this;
    if (!(this instanceof TrustWeb3Provider)) {
      that = window.ethereum;
    }
    if (Array.isArray(payload)) {
      Promise.all(payload.map((_payload) => that._request(_payload)))
        .then((data) => callback(null, data))
        .catch((error) => callback(error, null));
    } else {
      that
        ._request(payload)
        .then((data) => callback(null, data))
        .catch((error) => callback(error, null));
    }
  }

  /**
   * @private Internal rpc handler
   */
  _request(payload, wrapResult = true) {
    this.idMapping.tryIntifyId(payload);
    if (this.isDebug) {
      console.log(`==> _request payload ${JSON.stringify(payload)}`);
    }
    this.fillJsonRpcVersion(payload);
    return new Promise((resolve, reject) => {
      if (!payload.id) {
        payload.id = Utils.genId();
      }
      this.callbacks.set(payload.id, (error, data) => {

        console.log("tuanha", JSON.stringify(error), JSON.stringify(data))

        if (error) {
          reject(error);
        } else {
          resolve(data);
        }
      });
      this.wrapResults.set(payload.id, wrapResult);

      switch (payload.method) {
        case "eth_accounts":
          return this.sendResponse(payload.id, this.eth_accounts());
        case "eth_coinbase":
          return this.sendResponse(payload.id, this.eth_coinbase());
        case "net_version":
          return this.sendResponse(payload.id, this.net_version());
        case "eth_chainId":
          return this.sendResponse(payload.id, this.eth_chainId());
        case "eth_blockNumber":
          return this.sendResponse(payload.id, "0x1059678");
        case "eth_getBlockByNumber":
          return this.sendResponse(payload.id, {
            "baseFeePerGas": "0x790fe6326",
            "difficulty": "0x0",
            "extraData": "0xd883010b05846765746888676f312e32302e32856c696e7578",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0xb951f1",
            "hash": "0xafa89c3b4a65df8eaabdd4f2f105f31cfdae474e7e972d53085b7b0217c31b23",
            "logsBloom": "0x0a210917c3a91b225a88f060879b822814a462425e264229846361503a829808d837b36800221e8ccf121626c69813f40e0d9954c9a72c8982e60526982c26af48a2721c4433ddb8af23c22bca34b476425498c80bcc3a5d8c10353d8038a6a1eba249c492669005454c168c28657c550614226641b08c60320322b4a2ee80800854075b00109fc9c44c1e598b11437652200481e31f98cde4208456109117009ef893f4f748e6ca7b1340f0981605a59c614111c494c42a43456020242e884125154d03a61116e10b018d8145209132684c7fe644c8e8902a26612a1128607495306adc713006c0318526c827111903b254ab54d788165016117ae1d0211480",
            "miner": "0xe688b84b23f322a994a53dbf8e15fa82cdb71127",
            "mixHash": "0x4027d83125b56052853a66799dfd021908471e811c8a52fdf4be7ee02d2936bc",
            "nonce": "0x0000000000000000",
            "number": "0x10596a3",
            "parentHash": "0x1aff1862272091c98bc161301c36b34e1d5e2708b5bfd886419e5b873a67415d",
            "receiptsRoot": "0x5eb6ec62ed268e3986ab70ed9bee8aebe470459263860a89a43e001058449e0a",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "size": "0x114d2",
            "stateRoot": "0xc340df9b49d62fc696c6c63c044777df19570b76e8dda2a9afbd7ad74469eeab",
            "timestamp": "0x644b84bb",
            "totalDifficulty": "0xc70d815d562d3cfa955",
            "transactions": [
              "0x9ee769efe212c92782c48376fdc2da7ecb19b0f4f4475b294e7a63101b9b9e16",
              "0x36250eca5f57a2b2412f07f7fa5d67f01a6a87aa09d0a48d60ee57360cd3f810",
              "0x2db53bfd99bc4de78e4582d62e5a4cb0a3c24e86a53eef4ac7183d640e464268",
              "0xf2610e504485fbd3839a3fe2d905495589bf86056a4f7f1274c390aac07cf2d1",
              "0x9aa1b511faab0a5597958644058b99540d3f807a39be5b714391d1da4f229626",
              "0x3b8bbac75629ff55269164b090315ffb5f6d1a93f0c4a769f9887ab00c47246c",
              "0xcfd272df6d87ee634b56a8c03d687d4afedeb258c891eb2d417de5d3ecab1db9",
              "0xffc67b03a96d5a7bd58558b9cc3d2677804bfe60053de17fbd8cf6e81ea5fb63",
              "0x2b3e16cb94986b81cff17535cd19bc599736e2365620304750a3d8e01bc7c307",
              "0xfd6e91f94c778652cbf5d6b76c5ccb79babaed818dd928aa507e0c47ee43fd1f",
              "0x9111957db4da829c6a8ecaaa8f340c13cd06d61cb3f8e1d5543e0de7f7f13d7f",
              "0x144da0a87e74b24b284c98f540ae1b577b6bf7f28fcc5f483b416e0241991220",
              "0x157bada77e8bb7d1650f8b81e10785a957c33449822e256ec1beaeb91dc7cbef",
              "0xc489e9f3068ee9b52a30f26c108aff0a38b072412df07e5dc69071195681a2c8",
              "0xcd15144818c28a44e4e93d345bb31cdb348b76a624d069a4e9109dbf4cc828cc",
              "0x94a872ac69d79a710a45b269bb2650cc52d6f02994bea41ac93ade77eb54eebe",
              "0xf08411174e1ba3c2bc3a8c1050aa41709b30e5261dddaedf98a67b1a8e4b8b90",
              "0x2f4e4b32a755004fdd7b84f6823c9256c49df351d99952ad7e8e5438dd5f9b13",
              "0x567de7905fc4543b47fe343fd1c172217f5902ae06a031e50e84ae79dc0b2151",
              "0xd5f0aa2308d30724a0958fc41b7c545360a889275fbb4f015f364113abdd311e",
              "0x8015297ea2510644e4080ca8e7cfb1d7a485d2e19f9dc41ee0191f49c344c074",
              "0x3006e1fe16a35dcf19d84b139d43f7e412c5434ceae5c4741fde0b6a7821fb84",
              "0xc4bcfe1ac8831144ff427f543eaafb780300801813612fd708f8ea0d78760e8d",
              "0x329460f9fbfe014445ddc103985e392b74499c3797f6e7682787e9e10b9a90c5",
              "0x9020a7053b06df5855b623ad298ae0018c6cbb161ccb0395f49aa5c3eeb3c2bd",
              "0xb32fd7d256b4a6e1530a61d20cb301ba3a42a9f2076c6ed4470ebaa90a1e7bc7",
              "0xb5e03bd03e037e7e9dd23d741b73085e080f96217dff4ea66ee9848003e60dda",
              "0x423b75b590f7ddf8a7e6a1b1fca67ab1d73410cf6af7ebd1d01dd1925d9877f1",
              "0x86cf4e97bce4867215f9495d52d9bf34b692d0491e537391827ac78f50641286",
              "0x452f9c8a149ff13c2c8e84c3860704751d5c59a4bc156745d23ea4e33f289050",
              "0x6bb6d95c227fad9dac75391ac1b721ba8435a0e4798c8529a1e8f2676ca1e885",
              "0x53c523cc9ad461fe6735af37a5894f7ec307275fa46434a4c499836c1a5fcc29",
              "0x0aa31b0ebd173c54362192c6a64db7503fbab6d3f140213cfc6b5917dab12751",
              "0x8086fb6b5453b9e8b5b69a79945d2d67b9baad6739d6d4435749755cf830c49c",
              "0x15f27deb643b5ac450f6f686d935f664c2146999b3b1127cbe13051bbbabc3d9",
              "0x7df1278413816b2d3c7cc9d3d3d186420a8542dfc790810cbac9be28922f3cd2",
              "0x9d90fb363e3dd28516f44ab1cb7c3a7a60d6167ced2e8ef1a80a8460b0f4cb84",
              "0x598d3d1e5e132715d3983355981dec0d52ea4d9f05fd5cd3b353601650861b38",
              "0x588505bab1e53e9b7a593e735a91b23a095864fb4eb396306ab0c93c51d6e71a",
              "0x41a64cb15c4d94223bdc25f21145dcdaa8a1ea55574b70365c947c717772d5be",
              "0x78666af86e3227805c7926c83a539028f040c44fd6b5a1c5cfef6ce775cd4131",
              "0xe8c9c58960c7d40c32d54dae198daa8627f4a9a6bba006b3efdd667a280b944e",
              "0xda0ec43614c86ad721625482e8161a3eacdc08d60a50e3fb5f9b017cb4ee41b0",
              "0xf34ca4b5899753fdf53cd465bebe3b6283a43cb97708583477c1367f030592e1",
              "0xc4b227d784a223a738ac1edb33bf1c6cc4482aa1afa1617fd90c30e965f227c7",
              "0x594828874db2c3b6ca45edd37ddaf10d77d9f3b3775849537e75e349e3f9b438",
              "0xee024645af412024cbe7355b226b9b0f92cfee6f1787b3d9eba33fe4cd75b105",
              "0xfa847313aa8d2e5005afc6e25b8ebdf3e54b71b37c1a988e847f02a92b5c1fb7",
              "0x8154bdf801a3081cedfd785a188396412ad89b05deb228f2b3b261a8feac1797",
              "0x11fcd4b90cde822d718c3a4dc03202522e927e91029b2ee827153e751b2bc8ad",
              "0x433980b8752585cd613b421d8c2a311ecb2a4a475e5f675303bb572632d9de71",
              "0x48c7333286e85268d3fc8b02d7a0422174ac8dfea3f515eaba1cf80e144f8631",
              "0x66dbfb986c6b222fbce31246d2398b5eee5f74744d16604cea464a90fe47c1e8",
              "0x88d372905bd32fc25c36ef5a3304d5f0dc4b8724f99371273d36cf3fb6b7dd65",
              "0xe665b33eda9346136e4bbb40d699e3c00123f208730acdcbb5084ab06ff496d8",
              "0xc4f15202b7adcebb0bf6a62d8c1cfbfd85b027af790e2fe9543b1be389b43008",
              "0x73e4627a6e2cf0645cb8d08dc81ea176320b692bc86ea508d00f33b2b194f3e5",
              "0x9686add0aacfffdc42b3de2f332adc2262c4b172aa6f43b3d94e5f8dcc2887b2",
              "0x22297b14a51174a6f9eb05cfff22cdbc4e7c41bc94c933800817e44fc4f36663",
              "0xfded0d56dca59794f48b2c7eb5bb6355d38ac1120ebf5112b25c1f685f8bad29",
              "0x3ad355e753fb69ef6b09e966965242b70c42fa8651b8b318721d2d3d161433f1",
              "0x6b22a6fd09549fab060d37a2e65a97bc898575ecd275f00650e3bce1b4880a80",
              "0xae3483d49197708e06970ea754b2e2bdb45d49453db7b34dce281bac0faa2ae9",
              "0x8658abd03341e2e1ba88190b3b2cef478433298ca6d9f76a08ca32b8361ccad1",
              "0x333610b1244c7276a5dce02a787ea54dfbb1f2fdb963fe182b00ef3eaed76b72",
              "0x5c99f9bffa1b278a2c8b1a896b1123de007cbc7c7af152e62bcee7a808e89445",
              "0xf63688e51159ac23abe733cb2675c5437e67f954e1927f19ab9ecee201f660b6",
              "0x871cb515442c3cdb9ba59ce9e15a6836f282ad43d1117a4c857ee443ca92a0ac",
              "0x3a561968519e743befdc2f38d3ecc9fd0ea5539c64a54137032704648a9eada1",
              "0xfd705a21f71042fbebb98d54cae4333b023f8adb8fde0f25b69d8f7adbf22ad3",
              "0x8f734150d2fe41725be69d14f2a74f54895dc29b2bb89704af03d427249e37fd",
              "0x2a5b15a274be25833e89cc665e2f3d4a750080ae9b641899b282b2cdfeb95b0e",
              "0x07b6f2b7a5fcb0f9642532f308c07e15e705547a4ca0a3eecb336e41515f6b1f",
              "0x8c2108e8280017d83eae3dbc11764e0f520f41fcbc222d4d59e6ffdaefb88719",
              "0x9bea7bbf7683f2efb2ed11c1e7ff68196e69dd6503e04635f3c1065d924b630b",
              "0xa70de33c2c72a89d500ddf25d0f2d0cac5c9770adb88c7e519ae85b8018b2b11",
              "0xa77a398a83f5612d2eadd69a21db5b87ef7927d902aeb3ca52f6ae6f842b2e23",
              "0x8fbb4736b223395fb89e3b1fe21f80373afb8d38693f29235ff716f1c18fc52c",
              "0x096822854c467d03adc943ad82800f871cf56b156209a5dfd8c87b6c822e2c59",
              "0xaa8edc00b73a5003e5e22cf4317cc2b744a011a9e458e00e539e0a6ce0df7354",
              "0x88f08293fdcb4252c86e669067b456bc06feee771034c51124b1d6797c97eae1",
              "0x24be9ba601754ea21471f91995f4ae4232926e1ace015fe7891559be797d4403",
              "0x8b31c701e65816cf1597014c0ed7ddc524841180930dd44270ca442722a71932",
              "0x081c6b2b23cdb626ed77203b58058c17e0df1f973473ef1ea4f87152a6aa2260",
              "0x5ad1ba57e52f1909ec53a82c2605d140c7f088581f2ba7878a6e44a5ad852e4b",
              "0x5c565c97be22f2931ca31a88bf1c803c1fa4b19045924fd3f773c7c167b7c64e",
              "0xb3e45f7b48bbecdb2f915c9d89e0b5ab5ce72fce440e004d58f17cd054f28a2c",
              "0xc15ef86df734143aac045ae73efc030f6ba955c62f0fdad9242fe6e67c3d38a3",
              "0x272fad2a02c9c1e18040438f05a8fe680208d4441aea0e5b361594573c8a12d7",
              "0x6f78fd56a070de6abdfcf9c5b2ce5d651e60467a744fca79278d9283fb15839d",
              "0xa31423fa514b3815c78ab71ec394152c9039023f4b9a56c406c205eb88b7ea85",
              "0xc9e11791b24a11f701076bd992ac3e9a29a3c0118e12806d866632034e1b764c",
              "0x2182a52fba614c9840d08d16351f4c4c5afa919beebaa67f1cfff12dffb6c746",
              "0x38d73388b1d68d9381f765224d115415ee0b6f0225aa17f767debfd6a0c773d5",
              "0x5891f1c7f7cacc9a15ab344b40235f985e740abe5c6fa55af03b3df959ce08b8",
              "0xd326ab903114706c80c7a1da6dd3c4c1dc9947c5cc8fc0d7fd6bda6306323318",
              "0xa859a30f8a78d63a97dfeb60e2c8628adaa55140bb30342416975afde7544a57",
              "0x18dd1df614247efac753abec05779731085a2447f3c9603fd450f72026821a02",
              "0x5bfdbfc0e0c9e3c705ec2766f57cb6f760f36d7c5857f040009235f7d71c2672",
              "0x2aa60159a2388e35614aeaba9ac0a276edec467eef21a73a7d75e473a03cd12f",
              "0xebb42875ff63aa20fd718ead5a07637f03a2d0435cbcd84261162b47abd9c2f1",
              "0x0b46e62ba60a36f58d5da4fb6675ca26a182a00492d65076d780de48ac8fab0c",
              "0xfd5e0360cd3d75aa8dee6a69676bb705882aa4f42ecdeaed9a93d96a72a7981a",
              "0x2d4ea658c6e45f52a7909237cd2c16929f5e655daed98644ae8d7d94f468ec87",
              "0x510bd709e7bb276b97b989ed1061ea66edc97b70e99887105004d20d79a86660",
              "0x97fc64797140913fad7542d0c6263a5c04ab14e4591d5503cea605a1b1042e20",
              "0x24a0319929c7f6d2cbadac96c5c1f2d78808b04b6e5e289d0d093317abed2b01",
              "0xd26e44ff91a88934cb84c63bd8250ab65598a795f179ca33153699d1271433ef",
              "0xde243adeeb9214cc7003f73bf6f71e0d3dfe55f0c717e5af0384dd0b542365c2",
              "0x9f0eeb5695882311257a0ca0034305c414d98f51def2a52d4a75443452de3ba6",
              "0xa8cb4044fb3b220cd723b0b424559f1a73cd5e69dec11eb4297a16470942a445",
              "0xf46715e9e24007c0fa11d9028a116883b9ec26706e3a3adb8e9e4575e9d38d4d",
              "0x7004507d883f5422c747783f6d7339895861b31519d4ab9310dc6cde25ad5a33",
              "0x72f10f5aae134247c9578e1eebbb26c73c73aee89f973d6315555c1300a0f947",
              "0x54abda75abf2d852e2715559eeec3c595f6574d0af2bb1896cf771b55c0cdb8f",
              "0x4aed30c80ec4a0df63b3c3ca754d94858cf3c64d6ae6910882855461a5224cdd",
              "0xe6668bab7ff3161565a195190dcf874922167e3a0353eb3eb5e293694840df24",
              "0x8324b5dcf2ac8fd894285170676535af50be17e4ea5abb03a881d560fd81aa8b",
              "0x1dc2ee6afcebd8a50436f07f12ab19282dbc7872cc0b49ae5369ea6b69b0e76b",
              "0x379cf203d79efac49f60a3c6866a051d839bdf76010dcb789ed771cc4da530a7",
              "0x3f00011ea6fb7326aeb1695e82a3e6f0cb29b1b54785d78644bedb2326c69983",
              "0xbf185282233947c10e8dea804387338ef3722d4c80c5adc3705a99bef8e2eeec",
              "0xb7a7ee2bc7e3263c5cb59191a906da96ccf4825d25adf4d70e86120a7937a090",
              "0x43c77e150703df3f5693b9f13ae16e10ce7f069201df53de8b02af6d6f6cb4c0",
              "0x495b7de6b838dbb72291be42f3d555db38bec2d9d3027904a07018dace5940ed",
              "0xda6e435df5afca1b35d8cc3b03612cd621412e406a2926d4bd79a635bacd57c7",
              "0xc39f0307f706474d8a09b9e1a17f2e2c96c67faa9d6855da164a4f9f67fd96ef",
              "0x6a2caac756ee9d08e7a0b6e77bb585801ea6f1bac5b32953c9a793db48c6f20c",
              "0x7d3d3f199607058ddfd60117defc761b6605b400fc6974a1ca12462149c9eb9e",
              "0x403ae5e2919aca1db291d4d514480925e356c4a621a5b7c94cc4507bae28d22c",
              "0x15ff02e04805d0c96d0070cdd8c8b2594ec6c4b362e21cab971c25344e677fb7",
              "0xa9ef955e728fd0c9b828a23d87d9cc3ebf953869b87583e88b1d3687a3b9ed7a",
              "0x7d8dc49a5d8a05ca4af60951ccbcb1a5a3a167dc058a8f40733868da052ef3e6",
              "0x718e3b046f06e420d81d78f2a6e077428fc38864c9c4817ba1b64b41f86c4e6a",
              "0xec8032381dcb6bb50186d944cebe82759f42a60a49f279ae1f161e06bc2f04f4",
              "0x16742d1aa303ce0eba8a2f87958a11664e2bb168b341abded1a2b90c242371b1",
              "0x808e2f569d3107bd19cd5eb3ca6a87247b499a6aced4c2697f0dfc4eb5cc7abe",
              "0xccb48f27093b677bb96c96e5006fd03eabc185382c018aecfa9456d71b2562d2"
            ],
            "transactionsRoot": "0x718d817aa544404970361c966432a4cd704441f25803f9b67143a0b7e8882aa5",
            "uncles": [],
            "withdrawals": [
              {
                "index": "0x1a826d",
                "validatorIndex": "0x89c1e",
                "address": "0xb9d7934878b5fb9610b3fe8a5e441e8fad7e293f",
                "amount": "0xbc9582"
              },
              {
                "index": "0x1a826e",
                "validatorIndex": "0x89c1f",
                "address": "0xb9d7934878b5fb9610b3fe8a5e441e8fad7e293f",
                "amount": "0xbc4161"
              },
              {
                "index": "0x1a826f",
                "validatorIndex": "0x89c20",
                "address": "0xf9a3841da4dfd0b95674f94f24036ae132b15339",
                "amount": "0xbc64d9"
              },
              {
                "index": "0x1a8270",
                "validatorIndex": "0x89c21",
                "address": "0x58d15d2cad73045a078130c5aac9dd75167f604e",
                "amount": "0xbc50da"
              },
              {
                "index": "0x1a8271",
                "validatorIndex": "0x89c22",
                "address": "0x7e2a2fa2a064f693f0a55c5639476d913ff12d05",
                "amount": "0xbcc1d1"
              },
              {
                "index": "0x1a8272",
                "validatorIndex": "0x89c23",
                "address": "0x2b78035514401ed1592eb691b8673a93edf97470",
                "amount": "0xbd14e7"
              },
              {
                "index": "0x1a8273",
                "validatorIndex": "0x89c31",
                "address": "0xee3de3b314797fcaa771707849c8cdc491bf5ad5",
                "amount": "0xb9cf15"
              },
              {
                "index": "0x1a8274",
                "validatorIndex": "0x89c33",
                "address": "0xa157b222133562f7bb5c0ab20f42e5500703bc93",
                "amount": "0xbd308b"
              },
              {
                "index": "0x1a8275",
                "validatorIndex": "0x89c36",
                "address": "0x7e2a2fa2a064f693f0a55c5639476d913ff12d05",
                "amount": "0xbcabdb"
              },
              {
                "index": "0x1a8276",
                "validatorIndex": "0x89c3d",
                "address": "0x210b3cb99fa1de0a64085fa80e18c22fe4722a1b",
                "amount": "0xbaf314"
              },
              {
                "index": "0x1a8277",
                "validatorIndex": "0x89c3e",
                "address": "0x210b3cb99fa1de0a64085fa80e18c22fe4722a1b",
                "amount": "0xbbb0c1"
              },
              {
                "index": "0x1a8278",
                "validatorIndex": "0x89c44",
                "address": "0x3209b5344205c1c2a613295bf5ae283f32d610be",
                "amount": "0xbcf3cf"
              },
              {
                "index": "0x1a8279",
                "validatorIndex": "0x89c49",
                "address": "0x6c9d84728161e4527af33ff32447adbfeebcc354",
                "amount": "0xbc536b"
              },
              {
                "index": "0x1a827a",
                "validatorIndex": "0x89c4d",
                "address": "0x8972b6b9080b51d8bd9b65dca08574ffc6d91583",
                "amount": "0x2b9db65"
              },
              {
                "index": "0x1a827b",
                "validatorIndex": "0x89c66",
                "address": "0xc348b5dd7c64a47ef461cd325611b7b8155d16bc",
                "amount": "0xbbcc54"
              },
              {
                "index": "0x1a827c",
                "validatorIndex": "0x89c69",
                "address": "0x8306300ffd616049fd7e4b0354a64da835c1a81c",
                "amount": "0xbce62a"
              }
            ],
            "withdrawalsRoot": "0x9764ffcb73c93982355329fb2bfaf1b4c73bbd8d5b4d78045ee83a85b25693f9"
          });
        case "eth_sign":
          return this.eth_sign(payload);
        case "personal_sign":
          return this.personal_sign(payload);
        case "personal_ecRecover":
          return this.personal_ecRecover(payload);
        case "eth_signTypedData_v3":
          return this.eth_signTypedData(payload, SignTypedDataVersion.V3);
        case "eth_signTypedData_v4":
          return this.eth_signTypedData(payload, SignTypedDataVersion.V4);
        case "eth_signTypedData":
          return this.eth_signTypedData(payload, SignTypedDataVersion.V1);
        case "eth_estimateGas":
          return this.eth_estimateGas(payload);
        case "eth_sendTransaction":
          return this.eth_sendTransaction(payload);
        case "eth_requestAccounts":
          return this.eth_requestAccounts(payload);
        case "wallet_watchAsset":
          return this.wallet_watchAsset(payload);
        case "wallet_addEthereumChain":
          return this.wallet_addEthereumChain(payload);
        case "wallet_switchEthereumChain":
          return this.wallet_switchEthereumChain(payload);
        case "eth_newFilter":
        case "eth_newBlockFilter":
        case "eth_newPendingTransactionFilter":
        case "eth_uninstallFilter":
        case "eth_subscribe":
          throw new ProviderRpcError(
            4200,
            `Trust does not support calling ${payload.method}. Please use your own solution`
          );
        default:
          // call upstream rpc
          this.callbacks.delete(payload.id);
          this.wrapResults.delete(payload.id);
          return this.rpc
            .call(payload)
            .then((response) => {
              if (this.isDebug) {
                console.log(`<== rpc response ${JSON.stringify(response)}`);
              }
              wrapResult ? resolve(response) : resolve(response.result);
            })
            .catch(reject);
      }
    });
  }

  fillJsonRpcVersion(payload) {
    if (payload.jsonrpc === undefined) {
      payload.jsonrpc = "2.0";
    }
  }

  emitConnect(chainId) {
    this.emit("connect", { chainId: chainId });
  }

  emitChainChanged(chainId) {
    this.emit("chainChanged", "0x" + chainId.toString(16));
    this.emit("networkChanged", chainId);
  }

  emitAccountChanged(address) {
    this.emit("accountsChanged", [address]);
  }

  eth_accounts() {
    return this.address ? [this.address] : [];
  }

  eth_coinbase() {
    return this.address;
  }

  net_version() {
    return this.networkVersion;
  }

  eth_chainId() {
    return this.chainId;
  }

  eth_sign(payload) {
    const [address, message] = payload.params;
    const buffer = Utils.messageToBuffer(message);
    const hex = Utils.bufferToHex(buffer);

    if (isUtf8(buffer)) {
      this.postMessage("signPersonalMessage", payload.id, {
        data: hex,
        address,
      });
    } else {
      this.postMessage("signMessage", payload.id, { data: hex, address });
    }
  }

  personal_sign(payload) {
    var message;
    let address;

    if (this.address === payload.params[0].toLowerCase()) {
      message = payload.params[1];
      address = payload.params[0];
    } else {
      message = payload.params[0];
      address = payload.params[1];
    }
    const buffer = Utils.messageToBuffer(message);
    if (buffer.length === 0) {
      // hex it
      const hex = Utils.bufferToHex(message);
      this.postMessage("signPersonalMessage", payload.id, {
        data: hex,
        address,
      });
    } else {
      this.postMessage("signPersonalMessage", payload.id, {
        data: message,
        address,
      });
    }
  }

  personal_ecRecover(payload) {
    this.postMessage("ecRecover", payload.id, {
      signature: payload.params[1],
      message: payload.params[0],
    });
  }

  eth_signTypedData(payload, version) {
    let address;
    let data;

    console.log("tuanha", JSON.stringify(payload.params[0]))

    if (this.address === payload.params[0].toString().toLowerCase()) {
      data = payload.params[1];
      address = payload.params[0];
    } else {
      data = payload.params[0];
      address = payload.params[1];
    }

    const message = typeof data === "string" ? JSON.parse(data) : data;

    const { chainId } = message.domain || {};

    if (version != SignTypedDataVersion.V1 || chainId != undefined) if (!chainId || Number(chainId) !== Number(this.chainId)) {
      throw new Error(
        "Provided chainId does not match the currently active chain"
      );
    }

    const hash =
      version !== SignTypedDataVersion.V1
        ? TypedDataUtils.eip712Hash(message, version)
        : "";

    this.postMessage("signTypedMessage", payload.id, {
      data: "0x" + hash.toString("hex"),
      raw: typeof data === "string" ? data : JSON.stringify(data),
      address,
      version,
    });
  }

  eth_estimateGas(payload) {
    this.postMessage("estimateGas", payload.id, {});
  }

  eth_sendTransaction(payload) {
    this.postMessage("signTransaction", payload.id, payload.params[0]);
  }

  eth_requestAccounts(payload) {
    this.postMessage("requestAccounts", payload.id, {});
  }

  wallet_watchAsset(payload) {
    let options = payload.params.options;
    this.postMessage("watchAsset", payload.id, {
      type: payload.type,
      contract: options.address,
      symbol: options.symbol,
      decimals: options.decimals || 0,
    });
  }

  wallet_addEthereumChain(payload) {
    this.postMessage("addEthereumChain", payload.id, payload.params[0]);
  }

  wallet_switchEthereumChain(payload) {
    this.postMessage("switchEthereumChain", payload.id, payload.params[0]);
  }

  /**
   * @private Internal js -> native message handler
   */
  postMessage(handler, id, data) {
    if (this.ready || handler === "requestAccounts") {
      super.postMessage(handler, id, data);
    } else {
      // don't forget to verify in the app
      this.sendError(id, new ProviderRpcError(4100, "provider is not ready"));
    }
  }

  /**
   * @private Internal native result -> js
   */
  sendResponse(id, result) {
    let originId = this.idMapping.tryPopId(id) || id;
    let callback = this.callbacks.get(id);
    let wrapResult = this.wrapResults.get(id);
    let data = { jsonrpc: "2.0", id: originId };
    if (
      result !== null &&
      typeof result === "object" &&
      result.jsonrpc &&
      result.result
    ) {
      data.result = result.result;
    } else {
      data.result = result;
    }
    if (this.isDebug) {
      console.log(
        `<== sendResponse id: ${id}, result: ${JSON.stringify(
          result
        )}, data: ${JSON.stringify(data)}`
      );
    }
    if (callback) {
      wrapResult ? callback(null, data) : callback(null, result);
      this.callbacks.delete(id);
    } else {
      console.log(`callback id: ${id} not found`);
      // check if it's iframe callback
      for (var i = 0; i < window.frames.length; i++) {
        const frame = window.frames[i];
        try {
          if (frame.ethereum.callbacks.has(id)) {
            frame.ethereum.sendResponse(id, result);
          }
        } catch (error) {
          console.log(`send response to frame error: ${error}`);
        }
      }
    }
  }
}

module.exports = TrustWeb3Provider;

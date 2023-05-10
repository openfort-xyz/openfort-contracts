import "./aa.init";
import { ethers } from "hardhat";
import { Signer } from "ethers";
import {
  EntryPoint,
  EntryPoint__factory,
  OpenfortPluginSafe,
  OpenfortPluginSafe__factory,
  OpenfortGnosisSafeAccountFactory,
  OpenfortGnosisSafeAccountFactory__factory,
  GnosisSafeProxy,
  GnosisSafeProxyFactory__factory,
  TestCounter,
  TestCounter__factory,
  FunctionSignaturePolicy,
  FunctionSignaturePolicy__factory,
  FunctionSignaturePolicyFactory,
  FunctionSignaturePolicyFactory__factory,
  OpenfortSessionKeyPlugin__factory,
  OpenfortSessionKeyPlugin,
} from "../typechain";
import {
  createAddress,
  createAccountOwner,
  deployEntryPoint,
  getBalance,
  isDeployed,
} from "./testutils";
import { fillAndSign, fillUserOp, getUserOpHash } from "./UserOp";
import {
  defaultAbiCoder,
  hexConcat,
  hexZeroPad,
  parseEther,
} from "ethers/lib/utils";
import { expect } from "chai";
import { UserOperation } from "./UserOperation";

describe.only("Openfort Gnosis Proxy", function () {
  this.timeout(30000);

  let ethersSigner: Signer;
  let safeSingleton: OpenfortPluginSafe;
  let owner: Signer;
  let ownerAddress: string;
  let proxy: GnosisSafeProxy;
  let entryPoint: EntryPoint;
  let counter: TestCounter;
  let safe_execTxCallData: string;

  let accountFactory: OpenfortGnosisSafeAccountFactory;

  before("before", async function () {
    // EIP4337Manager fails to compile with solc-coverage
    if (process.env.COVERAGE != null) {
      return this.skip();
    }

    const provider = ethers.provider;
    ethersSigner = provider.getSigner();

    entryPoint = await deployEntryPoint();

    // standard safe singleton contract (implementation)
    safeSingleton = await new OpenfortPluginSafe__factory(ethersSigner).deploy(
      entryPoint.address
    );
    // standard safe proxy factory
    const proxyFactory = await new GnosisSafeProxyFactory__factory(
      ethersSigner
    ).deploy();
    owner = createAccountOwner();
    ownerAddress = await owner.getAddress();
    counter = await new TestCounter__factory(ethersSigner).deploy();

    accountFactory = await new OpenfortGnosisSafeAccountFactory__factory(
      ethersSigner
    ).deploy(proxyFactory.address, safeSingleton.address);

    const initCode = hexConcat([
      hexZeroPad(accountFactory.address, 20),
      accountFactory.interface.encodeFunctionData("createAccount", [
        ownerAddress,
        0,
      ]),
    ]);

    const expectedAddr = await entryPoint.callStatic
      .getSenderAddress(initCode)
      .catch((e) => {
        return e.errorArgs.sender;
      });

    console.log("EXPECTED :" + expectedAddr);

    await accountFactory.createAccount(ownerAddress, 0);
    // we use our accountFactory to create and configure the proxy.
    // but the actual deployment is done internally by the gnosis factory
    const ev = await proxyFactory.queryFilter(
      proxyFactory.filters.ProxyCreation()
    );
    const addr = ev[0].args.proxy;

    proxy = OpenfortPluginSafe__factory.connect(addr, owner);

    await ethersSigner.sendTransaction({
      to: proxy.address,
      value: parseEther("0.1"),
    });

    const counter_countCallData = counter.interface.encodeFunctionData("count");
    safe_execTxCallData = safeSingleton.interface.encodeFunctionData(
      "executeAndRevert",
      [counter.address, 0, counter_countCallData, 0]
    );
  });
  let beneficiary: string;
  beforeEach(() => {
    beneficiary = createAddress();
  });

  it("should fail from wrong entrypoint", async function () {
    // i don't know how to handle this properly i'll leave it a TODO
    const op = await fillAndSign(
      {
        sender: proxy.address,
      },
      owner,
      entryPoint,
      "getNonce"
    );

    const anotherEntryPoint = await new EntryPoint__factory(
      ethersSigner
    ).deploy();

    await expect(
      anotherEntryPoint.handleOps([op], beneficiary)
    ).to.revertedWith(
      'FailedOp(0, "AA23 reverted: account: not from entryPoint")'
    );
  });

  it("should fail on invalid userop", async function () {
    // await entryPoint.depositTo(proxy.address, { value: parseEther("1") });
    let op = await fillAndSign(
      {
        sender: proxy.address,
        nonce: 1234,
        callGasLimit: 1e6,
        callData: safe_execTxCallData,
      },
      owner,
      entryPoint,
      "getNonce"
    );
    await expect(entryPoint.handleOps([op], beneficiary)).to.revertedWith(
      "AA25 invalid account nonce"
    );
    op = await fillAndSign(
      {
        sender: proxy.address,
        callGasLimit: 1e6,
        callData: safe_execTxCallData,
      },
      owner,
      entryPoint,
      "getNonce"
    );
    // invalidate the signature
    op.callGasLimit = 1;
    await expect(entryPoint.handleOps([op], beneficiary)).to.revertedWith(
      'FailedOp(0, "AA24 signature error")'
    );
  });

  it("should exec", async function () {
    const op = await fillAndSign(
      {
        sender: proxy.address,
        callGasLimit: 1e6,
        callData: safe_execTxCallData,
      },
      owner,
      entryPoint,
      "getNonce"
    );

    const rcpt = await entryPoint
      .handleOps([op], beneficiary)
      .then(async (r) => r.wait())
      .catch((e) => {
        console.log("e=", e);
        throw e;
      });
    console.log("gasUsed=", rcpt.gasUsed, rcpt.transactionHash);

    const ev = rcpt.events!.find((ev) => ev.event === "UserOperationEvent")!;
    expect(ev.args!.success).to.eq(true);
    expect(await getBalance(beneficiary)).to.eq(ev.args!.actualGasCost);
  });

  it("should revert with reason", async function () {
    const counter_countFailCallData =
      counter.interface.encodeFunctionData("countFail");
    const safe_execFailTxCallData = safeSingleton.interface.encodeFunctionData(
      "executeAndRevert",
      [counter.address, 0, counter_countFailCallData, 0]
    );

    const op = await fillAndSign(
      {
        sender: proxy.address,
        callGasLimit: 1e6,
        callData: safe_execFailTxCallData,
      },
      owner,
      entryPoint,
      "getNonce"
    );
    const rcpt = await entryPoint
      .handleOps([op], beneficiary)
      .then(async (r) => r.wait());
    console.log("gasUsed=", rcpt.gasUsed, rcpt.transactionHash);

    // decode the revertReason
    const ev = rcpt.events!.find(
      (ev) => ev.event === "UserOperationRevertReason"
    )!;
    let message: string = ev.args!.revertReason;
    if (message.startsWith("0x08c379a0")) {
      // Error(string)
      message = defaultAbiCoder
        .decode(["string"], "0x" + message.substring(10))
        .toString();
    }
    expect(message).to.eq("count failed");
  });

  let counterfactualAddress: string;
  it("should create account", async function () {
    const initCode = hexConcat([
      accountFactory.address,
      accountFactory.interface.encodeFunctionData("createAccount", [
        ownerAddress,
        123,
      ]),
    ]);

    counterfactualAddress = await accountFactory.callStatic.getAddress(
      ownerAddress,
      123
    );
    expect(!(await isDeployed(counterfactualAddress)));

    await ethersSigner.sendTransaction({
      to: counterfactualAddress,
      value: parseEther("0.1"),
    });
    const op = await fillAndSign(
      {
        sender: counterfactualAddress,
        initCode,
        verificationGasLimit: 400000,
      },
      owner,
      entryPoint,
      "getNonce"
    );

    const rcpt = await entryPoint
      .handleOps([op], beneficiary)
      .then(async (r) => r.wait());
    console.log("gasUsed=", rcpt.gasUsed, rcpt.transactionHash);
    expect(await isDeployed(counterfactualAddress));

    const newCode = await ethers.provider.getCode(counterfactualAddress);
    expect(newCode.length).eq(324);
  });

  it("another op after creation", async function () {
    if (counterfactualAddress == null) this.skip();
    expect(await isDeployed(counterfactualAddress));

    const op = await fillAndSign(
      {
        sender: counterfactualAddress,
        callData: safe_execTxCallData,
      },
      owner,
      entryPoint,
      "getNonce"
    );

    const rcpt = await entryPoint
      .handleOps([op], beneficiary)
      .then(async (r) => r.wait());
    console.log("gasUsed=", rcpt.gasUsed, rcpt.transactionHash);
  });

  describe("policy session key", function () {
    let sessionKey: Signer;
    let userSignedUserOp: UserOperation;
    let policy: FunctionSignaturePolicy;
    let policyPlugin: OpenfortSessionKeyPlugin;
    // beforeEach(async function () {
    //   policy = await new FunctionSignaturePolicy__factory(ethersSigner).deploy([
    //     {
    //       to: counter.address,
    //       sig: counter.interface.getSighash("count"),
    //     },
    //   ]);

    //   policyPlugin = await new OpenfortSessionKeyPlugin__factory(
    //     ethersSigner
    //   ).deploy();
    //   sessionKey = createAccountOwner(); // use random session key
    //   const userOp = {
    //     sender: proxy.address,
    //     callGasLimit: 1e6,
    //     callData: safe_execTxCallData,
    //     verificationGasLimit: 1e6,
    //   };
    //   userSignedUserOp = await approvePlugin(
    //     owner,
    //     userOp,
    //     1777068462,
    //     0,
    //     policyPlugin.address,
    //     hexConcat([
    //       hexZeroPad(await sessionKey.getAddress(), 20),
    //       hexZeroPad(policy.address, 20),
    //     ]),
    //     entryPoint
    //   );
    //   // fund wallet some eth for gas
    //   await ethersSigner.sendTransaction({
    //     to: proxy.address,
    //     value: parseEther("10"),
    //   });
    // });

    // it("should exec", async function () {
    //   const signedUserOp = await signUserOpWithSessionKey(
    //     userSignedUserOp,
    //     sessionKey,
    //     policyPlugin,
    //     policy,
    //     entryPoint
    //   );

    //   const count_before = await counter.counters(proxy.address);
    //   const nonce_before = await getSessionNonce(
    //     policyPlugin,
    //     proxy.address,
    //     sessionKey
    //   );
    //   const rcpt = await entryPoint
    //     .handleOps([signedUserOp], beneficiary)
    //     .then(async (r) => r.wait());
    //   const ev = rcpt.events!.find((ev) => ev.event === "UserOperationEvent")!;
    //   expect(ev.args!.success).to.eq(true);
    //   expect(await counter.counters(proxy.address)).to.eq(count_before.add(1));
    //   const nonce_after = await getSessionNonce(
    //     policyPlugin,
    //     proxy.address,
    //     sessionKey
    //   );
    //   expect(nonce_after).to.be.eq(ethers.BigNumber.from(nonce_before).add(1));
    // });
    // it("should be able to exec multiple times with same user signature", async function () {
    //   let signedUserOp = await signUserOpWithSessionKey(
    //     userSignedUserOp,
    //     sessionKey,
    //     policyPlugin,
    //     policy,
    //     entryPoint
    //   );

    //   let count_before = await counter.counters(proxy.address);
    //   let nonce_before = await getSessionNonce(
    //     policyPlugin,
    //     proxy.address,
    //     sessionKey
    //   );
    //   let rcpt = await entryPoint
    //     .handleOps([signedUserOp], beneficiary)
    //     .then(async (r) => r.wait());
    //   let ev = rcpt.events!.find((ev) => ev.event === "UserOperationEvent")!;
    //   expect(ev.args!.success).to.eq(true);
    //   expect(await counter.counters(proxy.address)).to.eq(count_before.add(1));
    //   let nonce_after = await getSessionNonce(
    //     policyPlugin,
    //     proxy.address,
    //     sessionKey
    //   );
    //   expect(nonce_after).to.be.eq(ethers.BigNumber.from(nonce_before).add(1));

    //   signedUserOp = await signUserOpWithSessionKey(
    //     userSignedUserOp,
    //     sessionKey,
    //     policyPlugin,
    //     policy,
    //     entryPoint
    //   );

    //   count_before = await counter.counters(proxy.address);
    //   nonce_before = await getSessionNonce(
    //     policyPlugin,
    //     proxy.address,
    //     sessionKey
    //   );
    //   rcpt = await entryPoint
    //     .handleOps([signedUserOp], beneficiary)
    //     .then(async (r) => r.wait());
    //   ev = rcpt.events!.find((ev) => ev.event === "UserOperationEvent")!;
    //   expect(ev.args!.success).to.eq(true);
    //   expect(await counter.counters(proxy.address)).to.eq(count_before.add(1));
    //   nonce_after = await getSessionNonce(
    //     policyPlugin,
    //     proxy.address,
    //     sessionKey
    //   );
    //   expect(nonce_after).to.be.eq(ethers.BigNumber.from(nonce_before).add(1));
    // });
  });

  //   describe("function signature factory", function () {
  //     let factory: FunctionSignaturePolicyFactory;
  //     beforeEach(async function () {
  //       factory = await new FunctionSignaturePolicyFactory__factory(
  //         ethersSigner
  //       ).deploy();
  //     });

  //     it("should match address", async function () {
  //       const tx = await factory
  //         .deploy([
  //           {
  //             to: counter.address,
  //             sig: counter.interface.getSighash("count"),
  //           },
  //         ])
  //         .then(async (r) => r.wait());

  //       const policyAddress = tx?.events[0].args[0];

  //       expect(policyAddress).to.equal(
  //         await factory.getPolicy([
  //           {
  //             to: counter.address,
  //             sig: counter.interface.getSighash("count"),
  //           },
  //         ])
  //       );
  //     });
  //   });
});

async function getSessionNonce(
  plugin: OpenfortSessionKeyPlugin,
  sender: string,
  sessionKey: Signer
): Promise<number> {
  return await OpenfortPluginSafe__factory.connect(sender, plugin.provider)
    .callStatic.queryPlugin(
      plugin.address,
      plugin.interface.encodeFunctionData("sessionNonce", [
        await sessionKey.getAddress(),
      ])
    )
    .catch((e) => {
      if (e.errorName !== "QueryResult") {
        throw e;
      }
      return e.errorArgs.result;
    });
}

// async function approvePlugin(
//   owner: Signer,
//   userOp: Partial<UserOperation>,
//   validUntil: number,
//   validAfter: number,
//   pluginAddress: string,
//   data: string,
//   entryPoint?: EntryPoint
// ): Promise<UserOperation> {
//   const op = await fillAndSign(userOp, owner, entryPoint);
//   const provider = entryPoint?.provider;
//   const domain = {
//     name: "OpenfortPluginSafe",
//     version: "1.0.0",
//     verifyingContract: userOp.sender,
//     chainId: (await provider!.getNetwork()).chainId,
//   };
//   const value = {
//     sender: userOp.sender,
//     validUntil: validUntil,
//     validAfter: validAfter,
//     plugin: pluginAddress,
//     data: data,
//   };
//   const userSig = await owner._signTypedData(
//     domain,
//     {
//       ValidateUserOpPlugin: [
//         { name: "sender", type: "address" },
//         { name: "validUntil", type: "uint48" },
//         { name: "validAfter", type: "uint48" },
//         { name: "plugin", type: "address" },
//         { name: "data", type: "bytes" },
//       ],
//     },
//     value
//   );

//   const signature = hexConcat([
//     hexZeroPad(pluginAddress, 20),
//     hexZeroPad(validUntil, 6),
//     hexZeroPad(validAfter, 6),
//     userSig,
//   ]);
//   return {
//     ...op,
//     nonce: 0,
//     signature: signature,
//   };
// }

// async function signUserOpWithSessionKey(
//   userOp: UserOperation,
//   sessionKey: Signer,
//   plugin: OpenfortSessionKeyPlugin,
//   policy: FunctionSignaturePolicy,
//   entryPoint?: EntryPoint
// ): Promise<UserOperation> {
//   const op = await fillUserOp(userOp, entryPoint);
//   const provider = entryPoint?.provider;
//   const chainId = await provider!.getNetwork().then((net) => net.chainId);
//   const opHash = await getUserOpHash(op, entryPoint!.address, chainId);
//   const sessionDomain = {
//     name: "OpenfortSessionKeyPlugin",
//     version: "1.0.0",
//     verifyingContract: userOp.sender,
//     chainId: chainId,
//   };

//   const nonce = await getSessionNonce(plugin, userOp.sender!, sessionKey);
//   const sessionKeySig = await sessionKey._signTypedData(
//     sessionDomain,
//     {
//       Session: [
//         { name: "userOpHash", type: "bytes32" },
//         { name: "nonce", type: "uint256" },
//       ],
//     },
//     {
//       userOpHash: opHash,
//       nonce: nonce, // await plugin.sessionNonce(await sessionKey.getAddress())
//     }
//   );

//   return {
//     ...op,
//     signature: hexConcat([
//       op.signature,
//       ethers.utils.defaultAbiCoder.encode(
//         ["bytes", "bytes"],
//         [
//           hexConcat([
//             hexZeroPad(await sessionKey.getAddress(), 20),
//             hexZeroPad(policy.address, 20),
//           ]),
//           sessionKeySig,
//         ]
//       ),
//     ]),
//   };
// }

import { ethers } from "hardhat";

async function main() {
  const OpenfortSimpleAccount = await ethers.getContractFactory("OpenfortSimpleAccount");
  const openfortSimpleAccount = await OpenfortSimpleAccount.deploy("0xa6b71e26c5e0845f74c812102ca7114b6a896ab2");
  await openfortSimpleAccount.deployed();

  console.log(`OpenfortSimpleAccount deployed to ${openfortSimpleAccount.address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

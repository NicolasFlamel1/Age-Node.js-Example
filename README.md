# Age encryption and decryption Node.js example

I made this while researching age encryption and decryption. It's based off of the [age v1 doc](https://age-encryption.org/v1) and [rage library](https://github.com/str4d/rage).

This code can be ran with `node main.js` and demonstrates how to decrypt an encrypted Slatepack and how to age encrypt and decrypt arbitrary data.

Parts of this code were cleaned up and used to [add Grin encrypted Slatepack support to Ledger Live Desktop](https://github.com/NicolasFlamel1/ledger-live/blob/develop/libs/ledger-live-common/src/families/mimblewimble_coin/api/age.ts), to [test the Slatepack decryption functionality of the Grin Ledger app](https://github.com/NicolasFlamel1/Ledger-MimbleWimble-Coin/blob/all-supported-cryptocurrencies/tests/functional_tests/age.js), and to [test the Slatepack decryption functionality of the Grin Trezor firmware](https://github.com/NicolasFlamel1/trezor-firmware/blob/main/tests/mimblewimble_coin/functional_tests/age.js).

## Windows Tampering Plugin presentation
-------------------------------------

### Motivation
EDRs are nowadays an essential part of the IT echosystem, constituting a crucial piece to mantain security across devices such as PC clients, Servers, Mobiles, etc...

Since EDRs are involving kernel-space usage (the infamous ring 0) to ensure the ability to keep the best possible protection against malwares and threats, which attempts to use DKOM or other techniques at kernel-level space to perform malicious activities with the highest possible privileges they can gain.

Due to the rapidly evolving scenario of the Defense Evasion techniques, tampering is surely one of the most interesting and challenging.

That said, I decided to take the opportunity of the Volatility Plugin Contest 2024 to build a plugin that could easily group all the registry keys that a malware intends to edit in order to tamper one of the most famous EDR solutions: Microsoft Windows Defender.

The Tampering plugin allows to rapidly detect the most important registry keys and check if their data values are different other than standard ones, which could mean a possible tampering has occured.
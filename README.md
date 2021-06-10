# pyrat.py

## Description

pyrat is the ancestor of Scapy. This prototype contains several founding concepts:
- protocol stacking using the `+` operator
- default values
- simple packet injection

## Usage

On Linux, an ARP message can be defined and sent using:
```
sudo python2.7 pyrat.py 
Welcome to PyRat
>>> send(Ether() + ARP() + "pyrat was here!")
```

# Pikabot Bot ID Generation Code

# Description
This Python script replicates the algorithm used to generate a unique Pikabot bot ID as described in our blog [here](https://www.zscaler.com/blogs/security-research/technical-analysis-pikabot).

# Usage
```
usage: generate_botid.py [-h] -cn COMPUTER_NAME -u USERNAME -p PRODUCT -vsi VOLUME_SERIAL_ID

optional arguments:
-h, --help  show this help message and exit
-cn COMPUTER_NAME, --computer_name COMPUTER_NAME (Computer name of compromised host)
-u USERNAME, --username USERNAME (Username of compromised host)
-p PRODUCT, --product PRODUCT (Windows product version. This is the buffer of variable 'pdwReturnedProductType' of GetProductInfo)
-vsi VOLUME_SERIAL_ID, --volume_serial_id VOLUME_SERIAL_ID (Volume serial number of C: drive)
```

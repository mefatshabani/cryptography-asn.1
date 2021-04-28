# cryptography-asn.1

# What is ASN.1
ASN.1 is a standard interface description language for defining data structuresthat can be serialized and deserialized in a cross-platform way.  It is broadly usedin telecommunications and computer networking, and especially in cryptography.

Implementation of ASN.1 DER encoder that can encode subset of ASN.1 types by implementing these functions:

1. asn1_boolean(bool) <br>
2. asn1_integer(i) <br>
3. asn1_bitstring(bitstr) <br>
4. asn1_octetstring(octets) <br>
5. asn1_null() <br>
6. asn1_objectidentifier(oid) <br>
7. asn1_sequence(der) <br>
8. asn1_set(der) <br>
9. asn1_printablestring(string) <br>
10. asn1_utctime(time) <br>
11. asn1_tag_explicit(der, tag) <br>
12. asn1_len(content) <br>


# Testing the code

1. $ chmod +x asn1_encoder.py
2. $ chmod +x test_asn1_encoder.py
3. $ sed -i 's/\r//g' test_asn1_encoder.py
4. $ ./test_asn1_encoder.py
5. $ ./test_asn1_encoder.py 1 1 1

# sed -i 's/\r//g' Explenation 
Depending the OS where you are modifying the, characters (like \r) could be added to 
the code, breaking functionality. In that case, we would need first to run: sed -i 's/\r//g'

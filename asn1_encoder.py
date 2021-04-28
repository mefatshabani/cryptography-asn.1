#!/usr/bin/env python3
import sys

def nb(i):
    # helper function, transforms i:int into hexarray
    accum = []
    while i:
       accum.insert(0, i & 255)
       i >>= 8    
    return accum

def bitstr_to_int(bitstring):
    i = 0
    for bit in bitstring:
        i <<= 1
        if bit == '1':
            i|= 1
    return i
       
def most_significant_0s_handling(bitstring):
    # helper function, outputs how many 0s should be prepended
    # this is needed because these values are lost when passed to int
    # input should be already padded
    # returns hex null strings to prepend
    L = len(bitstring)
    if L == 0 or bitstring[0] == '1':
        return []
    else:
        i = 0
        while (bitstring[i] == '0'):
            i += 1
            if i == L:                
                break
        return [0 for x in range(i // 8)]  

def asn1_len(value_bytes):
    # helper function - should be used in other functions to calculate length octet(s)
    # value_bytes - bytes containing TLV value byte(s)
    # returns length (L) byte(s) for TLV
    L = len(value_bytes)
    if L < 128:
         return bytes([L])
    else:
        L_bitstring = nb(L)
        L_bitstring.insert(0, len(L_bitstring) | 128)
        return bytes(L_bitstring)

def asn1_boolean(bool):
    # BOOLEAN encoder has been implemented for you
    if bool:
        bool = b'\xff'
    else:
        bool = b'\x00'
    return bytes([0x01]) + asn1_len(bool) + bool

def asn1_null():
    # returns DER encoding of NULL
    return bytes([0x05]) + b'\x00'

def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER    
    if i == 0:
        i_bytes = b'\x00'
    else:
        i_hexarray = nb(i)
        if i_hexarray[0] > 127:
            i_hexarray.insert(0, 0)
        i_bytes = bytes(i_hexarray)    
    L_bytes = asn1_len(i_bytes)     
    return bytes([0x02]) + L_bytes + i_bytes

def asn1_bitstring(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING    
    L = len(bitstr)
    # Padding size calculation
    pad_bool = L % 8
    if not pad_bool:
        p_size = 0
    else:
        complete_bytes_number = L // 8
        p_size = 8 - L + (complete_bytes_number << 3)           
    # Pad, then Encode
    bitstr = bitstr + '0'*p_size
    # 0s to prepend
    zeros_to_add = most_significant_0s_handling(bitstr)
    # Transforming to hexarray, most significant 0s will be lost
    bitstr_int = bitstr_to_int(bitstr)
    bitstr_hexarray = nb(bitstr_int)
    bitstr_hexarray = zeros_to_add + bitstr_hexarray              
    # len parameter also considers the padding len byte
    bitstr_hexarray_for_len = [x for x in bitstr_hexarray]
    bitstr_hexarray_for_len.append(p_size)            
    return bytes([0x03]) + asn1_len(bitstr_hexarray_for_len) \
        + bytes([p_size]) + bytes(bitstr_hexarray)

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING    
    return bytes([0x04]) + asn1_len(octets) + octets

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER    
    first_byte_int = 40*oid[0] + oid[1]
    first_byte_hexarray = nb(first_byte_int)
    encoded_hexarrays = []
    for i in oid[2:][::-1]:
        encoded_hexarrays.insert(0, i & 127)
        while i > 127:
            i >>= 7
            encoded_hexarrays.insert(0, 128 | (i & 127))
    encoded_hexarrays = first_byte_hexarray + encoded_hexarrays        
    return bytes([0x06]) + asn1_len(encoded_hexarrays) + bytes(encoded_hexarrays)

def asn1_sequence(der):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE    
    return bytes([0x30]) + asn1_len(der) + der

def asn1_set(der):
    # der - DER bytes to encapsulate into set
    # returns DER encoding of SET
    return bytes([0x31]) + asn1_len(der) + der

def asn1_printablestring(string):
    # string - bytes containing printable characters (e.g., b"foo")
    # returns DER encoding of PrintableString    
    return bytes([0x13]) + asn1_len(string) + string

def asn1_utctime(time):
    # time - bytes containing timestamp in UTCTime format (e.g., b"121229010100Z")
    # returns DER encoding of UTCTime
    return bytes([0x17]) + asn1_len(time) + time

def asn1_tag_explicit(der, tag):
    type_int = 160 + tag    
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type
    return bytes([type_int]) + asn1_len(der) + der


# figure out what to put in '...' by looking on ASN.1 structure required (see slides)
asn1 = asn1_tag_explicit(asn1_sequence(asn1_set(asn1_integer(5) + \
       asn1_tag_explicit(asn1_integer(200), 2) + asn1_tag_explicit(asn1_integer(65407), 11)) + \
       asn1_boolean(True) + asn1_bitstring("011") + asn1_octetstring(b"\x00" + b"\x01" + b"\x02"*49) + \
       asn1_null() + asn1_objectidentifier([1,2,840,113549,1]) + \
       asn1_printablestring(b"hello.") + asn1_utctime(b"250223010900Z")), 0)
open(sys.argv[1], 'wb').write(asn1)

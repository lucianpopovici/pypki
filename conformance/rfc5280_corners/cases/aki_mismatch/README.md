# aki_mismatch

The AKI in the leaf cert references the wrong CA public key. RFC 5280 §4.2.1.1 requires AKI to match the issuer's SKI.

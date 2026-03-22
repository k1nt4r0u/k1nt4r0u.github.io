---
title: "PicoMini_by_CMU_Africa"
date: 2025-12-25T22:30:47+07:00
draft: false
tags: ["ctf", "re"]
categories: ["CTF Name"]
contest: "PicoMini_by_CMU_Africa"
author: "k1nt4r0u"
description: "Two Android reversing solves from PicoMini by following the actual app artifacts instead of the obvious screens"
---

# PicoMini by CMU Africa

This set had two Android reversing challenges. Both of them became much easier once I stopped staring at the default UI and followed the data that the APK already exposed.

## M1n10n'5_53cr37

### First pass

I started by opening `minions.apk` in `jadx-gui` and checking `MainActivity`, which is usually the first useful place in beginner Android reversing.

In this case it was mostly noise. Nothing there explained where the flag was hidden.

The first real clue came from the hint:

> Any interesting source files?

That pushed me toward text search instead of static browsing. Searching for `interesting` turned up this string:

```xml
android:text="Look into me my Banana Value is interesting"
```

So the next question became simple: where is `Banana Value` stored?

### Pivot

A second text search for `Banana` found the string resource:

```xml
<string name="Banana">OBUWG32DKRDHWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=</string>
```

That blob looked like Base32 immediately. Decoding it gave the flag directly:

```text
picoCTF{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}
```

### Takeaway

The only thing that mattered here was not trusting the activity layout as the whole challenge. The flag was never hidden behind complex code. It was just sitting in resources with a hint pointing at it.

## Pico Bank

### First clue

For `pico-bank.apk`, I again started in `MainActivity`, and this time the transaction list stood out right away:

```java
this.transactionList.add(new Transaction("Grocery Shopping", "2023-07-21", "$ 1110000", false));
this.transactionList.add(new Transaction("Electricity Bill", "2023-07-20", "$ 1101001", false));
this.transactionList.add(new Transaction("Salary", "2023-07-18", "$ 1100011", true));
...
```

Those amounts were clearly not normal balances. They looked like binary.

Converting the values to ASCII recovered the first half of the flag:

```text
picoCTF{1_l13d_4b0ut_b31ng_
```

That established the pattern, but the flag was incomplete, so the rest had to be somewhere else in the app.

### Second clue

The challenge hint mentioned the OTP flow, so I searched for `OTP` in the decompiled sources and resources.

That led to:

```xml
<string name="otp_value">9673</string>
```

and to the `verifyOtp` logic:

```java
public void verifyOtp(String otp) throws JSONException {
        String endpoint = "your server url/verify-otp";
        if (getResources().getString(R.string.otp_value).equals(otp)) {
            Intent intent = new Intent(this, (Class<?>) MainActivity.class);
            startActivity(intent);
            finish();
        } else {
            Toast.makeText(this, "Invalid OTP", 0).show();
        }
        JSONObject postData = new JSONObject();
        postData.put("otp", otp);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(1, endpoint, postData, ...);
        this.requestQueue.add(jsonObjectRequest);
}
```

The important detail here was that the app still POSTed the OTP to the backend, and the backend response included the missing flag chunk. At that point the local OTP value was all I needed.

### Getting the second half

I sent the discovered OTP to the endpoint directly:

```python
import requests

payload = {"otp": 9673}
r = requests.post("http://saffron-estate.picoctf.net:56247/verify-otp", data=payload)
print(r.text)
```

The server responded with:

```json
{"success":true,"message":"OTP verified successfully","flag":"s3cur3d_m0b1l3_l0g1n_c0085c75}","hint":"The other part of the flag is hidden in the app"}
```

Combining both parts produced the full flag:

```text
picoCTF{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_c0085c75}
```

## Final takeaway

Both APKs rewarded the same habit:

- search the app resources instead of only reading the main activity
- treat weird constants as data first, not as UI decoration
- follow the client/server boundary when the app hints at network validation

Once those pivots were clear, neither challenge needed anything more complicated than text search, decoding, and one short request script.

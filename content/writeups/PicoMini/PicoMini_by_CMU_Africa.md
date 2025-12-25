---
title: "PicoMini_by_CMU_Africa"
date: 2025-12-25T22:30:47+07:00
draft: false
tags: ["ctf", "re"]
categories: ["CTF Name"]
contest: "PicoMini_by_CMU_Africa"
author: "k1nt4r0u"
description: "Description: "
---

## M1n10n'5_53cr37

Sau khi decompile file `minions.apk` bằng jadx-gui ta được các source files, kiểm tra file `MainActivity` nhưng có vẻ file không có gì hữu ích trong việc tìm flag

Từ hint 2 : `Any interesting source files?` -> `Navigation` -> `Text search` -> tìm với từ khóa `"interesting"`

```
android:text="Look into me my Banana Value is interesting"
```

Vậy nhiệm vụ tiếp theo là tìm xem `Banana Value` là gì bằng cách tiếp tục sử dụng text search để tìm bằng các từ khóa như `Banana`, `Banana Value`, `Value`, `bananavalue`,...

```
<string name="Banana">OBUWG32DKRDHWMLUL53TI43OG5PWQNDSMRPXK3TSGR3DG3BRNY4V65DIGNPW2MDCGFWDGX3DGBSDG7I=</string>
```

Sau khi search thì ta có thể thấy `Banana Value` là 1 đoạn text được mã hóa dưới dạng `base32` -> sử dụng tool online để giải mã

`picoCTF{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}`

## Pico Bank

Sử dụng jadx-gui để decompile file `pico-bank.apk`, kiểm tra file `MainActivity`
```java
TextView welcomeMessage = (TextView) findViewById(R.id.welcomeMessage);
        welcomeMessage.setText("Welcome, Johnson");
        TextView myBalanceAmount = (TextView) findViewById(R.id.myBalanceAmount);
        myBalanceAmount.setText("$ 50,000,000");
        this.transactionsRecyclerView = (RecyclerView) findViewById(R.id.transactionsRecyclerView);
        this.transactionsRecyclerView.setLayoutManager(new LinearLayoutManager(this));
        this.transactionList = new ArrayList();
        this.transactionList.add(new Transaction("Grocery Shopping", "2023-07-21", "$ 1110000", false));
        this.transactionList.add(new Transaction("Electricity Bill", "2023-07-20", "$ 1101001", false));
        this.transactionList.add(new Transaction("Salary", "2023-07-18", "$ 1100011", true));
        this.transactionList.add(new Transaction("Internet Bill", "2023-07-17", "$ 1101111", false));
        this.transactionList.add(new Transaction("Freelance Payment", "2023-07-16", "$ 1000011", true));
        this.transactionList.add(new Transaction("Dining Out", "2023-07-15", "$ 1010100", false));
        this.transactionList.add(new Transaction("Gym Membership", "2023-07-14", "$ 1000110", false));
        this.transactionList.add(new Transaction("Stocks Dividend", "2023-07-13", "$ 1111011", true));
        this.transactionList.add(new Transaction("Car Maintenance", "2023-07-12", "$ 110001", false));
        this.transactionList.add(new Transaction("Gift Received", "2023-07-11", "$ 1011111", true));
        this.transactionList.add(new Transaction("Rent", "2023-07-10", "$ 1101100", false));
        this.transactionList.add(new Transaction("Water Bill", "2023-07-09", "$ 110001", false));
        this.transactionList.add(new Transaction("Interest Earned", "2023-07-08", "$ 110011", true));
        this.transactionList.add(new Transaction("Medical Expenses", "2023-07-07", "$ 1100100", false));
        this.transactionList.add(new Transaction("Transport", "2023-07-06", "$ 1011111", false));
        this.transactionList.add(new Transaction("Bonus", "2023-07-05", "$ 110100", true));
        this.transactionList.add(new Transaction("Subscription Service", "2023-07-04", "$ 1100010", false));
        this.transactionList.add(new Transaction("Freelance Payment", "2023-07-03", "$ 110000", true));
        this.transactionList.add(new Transaction("Entertainment", "2023-07-02", "$ 1110101", false));
        this.transactionList.add(new Transaction("Groceries", "2023-07-01", "$ 1110100", false));
        this.transactionList.add(new Transaction("Insurance Premium", "2023-06-28", "$ 1011111", false));
        this.transactionList.add(new Transaction("Charity Donation", "2023-06-26", "$ 1100010", true));
        this.transactionList.add(new Transaction("Vacation Expense", "2023-06-26", "$ 110011", false));
        this.transactionList.add(new Transaction("Home Repairs", "2023-06-24", "$ 110001", false));
        this.transactionList.add(new Transaction("Pet Care", "2023-06-22", "$ 1101110", false));
        this.transactionList.add(new Transaction("Personal Loan", "2023-06-18", "$ 1100111", true));
        this.transactionList.add(new Transaction("Childcare", "2023-06-15", "$ 1011111", false));
        this.transactionAdapter = new TransactionAdapter(this.transactionList);
        this.transactionsRecyclerView.setAdapter(this.transactionAdapter);
```

Có thể thấy đây là lịch sử thanh toán của ông Johnson và số tiền trong những lần thanh toán của ông chính là mã nhị phân

Dịch ra text thì ta được nửa đầu của flag `picoCTF{1_l13d_4b0ut_b31ng_` 

Tiếp tục sử dụng `Text search` -> tìm `"OTP"`
```
<string name="otp_value">9673</string>
```
Vậy `OTP` là `9673`

Trong file `MainActivity` có thêm hint: `Have you analyzed the server's response when handling OTP requests?`

Tiếp tục sử dụng `Text search` tìm `OTP` thì ta thấy 1 đoạn code có vẻ như là kiểm tra otp nhập vào 
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
        try {
            postData.put("otp", otp);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(1, endpoint, postData, new Response.Listener<JSONObject>() { // from class: com.example.picobank.OTP.2
            @Override // com.android.volley.Response.Listener
            public void onResponse(JSONObject response) throws JSONException {
                try {
                    boolean success = response.getBoolean("success");
                    if (success) {
                        String flag = response.getString("flag");
                        String hint = response.getString("hint");
                        Intent intent2 = new Intent(OTP.this, (Class<?>) MainActivity.class);
                        intent2.putExtra("flag", flag);
                        intent2.putExtra("hint", hint);
                        OTP.this.startActivity(intent2);
                        OTP.this.finish();
                    } else {
                        Toast.makeText(OTP.this, "Invalid OTP", 0).show();
                    }
                } catch (JSONException e2) {
                    e2.printStackTrace();
                }
            }
        }, new Response.ErrorListener() { // from class: com.example.picobank.OTP.3
            @Override // com.android.volley.Response.ErrorListener
            public void onErrorResponse(VolleyError error) {
            }
        });
        this.requestQueue.add(jsonObjectRequest);
    }
```
Đọc code ta thấy khi `POST` lên server với endpoint là `your server url/verify-otp`  và data là `OTP`, server sẽ check xem `OTP` nhập vào đúng hay sai, nếu đúng nó sẽ cho `response` là flag vậy nên ta chỉ cần `POST` với data là `OTP` tìm thấy ở trên ta sẽ có được phần còn lại của flag cần tìm
```python
import requests
import json
payload = {"otp": 9673}
r = requests.post('http://saffron-estate.picoctf.net:56247/verify-otp', data = payload)
print(r.text)
```
Chạy script thì response trả về là phần còn lại của flag
```
{"success":true,"message":"OTP verified successfully","flag":"s3cur3d_m0b1l3_l0g1n_c0085c75}","hint":"The other part of the flag is hidden in the app"}
```
`picoCTF{1_l13d_4b0ut_b31ng_s3cur3d_m0b1l3_l0g1n_c0085c75}`

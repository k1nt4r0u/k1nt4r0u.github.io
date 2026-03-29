---
title: "{{ replace .Name "-" " " | title }}" 
date: {{ .Date }}
draft: false
tags: ["CTF", "RE"]
categories: ["{{ replace .Name "-" " " | title }}"]
contest: "{{ replace .Name "-" " " | title }}"
author: "k1nt4r0u"
description: "A detailed writeup for {{ replace .Name "-" " " | title }} challenge"
difficulty: "Easy/Medium/Hard"
---



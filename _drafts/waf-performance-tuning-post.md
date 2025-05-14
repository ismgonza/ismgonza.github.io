---
layout: post
title: WAF, Performance Tuning and Operator Optimization
date: 2025-01-20 10:00
author: Isma
categories: security waf
tags: security waf guides performance
duration: 9 minutes
banner_image: '/assets/images/waf_4_performance_banner.jpg'
banner_image_credits: '_Photo by [Michael Dziedzic](https://unsplash.com/@lazycreekimages?utm_content=creditCopyText&utm_medium=referral&utm_source=unsplash) on [Unsplash](https://unsplash.com/photos/a-close-up-of-a-speedometer-on-a-dashboard-qpC-Opte1Ps)_'
---

After our previous dive into rule tuning for accuracy, I've had several questions from readers about performance impact. One reader wrote: "Great tips on reducing false positives, but my WAF is slowing down our site. Help!"

I can relate. Years ago, I inherited a WAF setup that was so poorly optimized it added a full second to every page load. The security was solid, but users were abandoning the site because of the speed issues. The business was literally losing money with each blocked attack – not exactly what we want from security tools.

So today, we're tackling the other critical aspect of WAF tuning: **performance optimization**. We'll explore how different operators affect processing speed and how to make your WAF more efficient without compromising security.

## Understanding the Performance Impact of WAF

Before we dive into optimization techniques, let's understand why WAF can impact performance:

1. **Every HTTP Transaction Gets Inspected**: Your WAF examines every request and (potentially) every response
2. **Regular Expression Evaluation Is Expensive**: Complex pattern matching requires significant CPU time
3. **Rules Execute Sequentially**: The more rules you have, the longer processing takes
4. **Body Processing Adds Overhead**: Especially for large request/response bodies

On a busy server, these factors can compound quickly. I've seen poorly configured WAFs cause 30%+ increases in server CPU usage and measurable increases in response time.

## The Performance Hierarchy of ModSecurity Operators

Not all operators are created equal when it comes to performance. Here's a breakdown of common operators from fastest to slowest:

### 1. String Operators (Fastest)

```modsec
# Fast: Simple string comparison
SecRule REQUEST_URI "@streq /admin.php" "id:10001,phase:1,deny"
```

String operators like `@eq`, `@streq`, and `@endsWith` are lightning fast because they perform simple comparisons without complex pattern matching.

### 2. Numerical Comparison Operators

```modsec
# Fast: Numerical comparison
SecRule CONTENT_LENGTH "@gt 10000000" "id:10002,phase:1,deny"
```

Operators like `@lt`, `@gt`, and `@eq` for numerical values are very efficient.

### 3. IP Matching Operators

```modsec
# Fairly fast: IP matching
SecRule REMOTE_ADDR "@ipMatch 192.168.1.0/24" "id:10003,phase:1,allow"
```

The `@ipMatch` operator is optimized for IP comparisons and performs well.

### 4. Multi-Pattern Matching (@pm)

```modsec
# Good performance for multiple values
SecRule ARGS_NAMES "@pm admin user pass pwd" "id:10004,phase:2,deny"
```

The `@pm` operator is remarkably efficient for checking multiple patterns. It uses an algorithm called Aho-Corasick that can check thousands of patterns in a single pass through the input.

### 5. Simple Regular Expressions

```modsec
# Moderate performance
SecRule REQUEST_URI "@rx ^/(admin|config|setup)" "id:10005,phase:1,deny"
```

Simple regex patterns with basic character classes and alternations have reasonable performance.

### 6. Complex Regular Expressions (Slowest)

```modsec
# Slow: Complex backtracking regex
SecRule REQUEST_BODY "@rx (?:((?:\W*?(\bselect\b)\W*?(\bdistinct\b)?)|(?:\W*?(\binsert\b)\W*?(\binto\b))|(?:\W*?(\bupdate\b)\W*?)|(?:\W*?(\bdelete\b)\W*?(\bfrom\b)))\W*?)+?.*?" "id:10006,phase:2,deny"
```

Complex regexes with lookaheads, lookbehinds, and heavy backtracking can bring your server to its knees.

## Performance Comparison: @rx vs @pm

Let's talk about the big two pattern matching operators: `@rx` (regex) and `@pm` (pattern match). This performance difference is so significant it deserves special attention.

### Regex (@rx) Performance Characteristics:
- **Flexible**: Can match complex patterns
- **Powerful**: Captures subexpressions, handles character classes
- **CPU Intensive**: Backtracking can cause exponential time complexity
- **Sequential**: Checks one pattern at a time

### Pattern Match (@pm) Performance Characteristics:
- **Limited**: Only does literal string matching (no wildcards)
- **Fixed Patterns**: Cannot handle partial matches or regex tricks
- **Highly Optimized**: Uses Aho-Corasick algorithm
- **Parallel**: Checks all patterns in a single pass

### Real-World Performance Difference

In testing I performed on a moderate traffic site (about 500 req/sec):

```modsec
# Test 1: Regular Expression
SecRule ARGS:q "@rx (user|admin|root|superuser)" "id:10007,phase:2,pass,nolog"

# Test 2: Pattern Match (equivalent)
SecRule ARGS:q "@pm user admin root superuser" "id:10008,phase:2,pass,nolog"
```

The results were striking:
- The `@rx` version added ~3ms processing time per request
- The `@pm` version added only ~0.4ms per request
- At scale, this was a difference of 1.5 seconds vs 0.2 seconds of CPU time per 500 requests

**When should you use each?**
- Use `@pm` whenever you're just looking for exact strings
- Reserve `@rx` for when you need pattern flexibility

## Practical Performance Optimization Techniques

Now that we understand the performance characteristics, let's look at practical techniques for optimization:

### 1. Use Early Phase Rules to Minimize Processing

```modsec
# Phase 1 rule to block bad bots before wasting resources
SecRule REQUEST_HEADERS:User-Agent "@pm masscan nmap zgrab" \
    "id:10009,phase:1,deny,status:403,msg:'Scanner detected'"
```

This rule blocks malicious scanners based on User-Agent before wasting resources processing their requests further.

### 2. Convert Complex Regex Rules to Multi-Stage Rules

Instead of:

```modsec
# Inefficient: Complex regex
SecRule ARGS:input "@rx (?:union\s+all.*?select)|(?:;\s*?select\s+.*?from)" \
    "id:10010,phase:2,deny,msg:'SQL Injection'"
```

Consider:

```modsec
# Efficient: Two-stage detection
SecRule ARGS:input "@pm union ; select from" \
    "id:10010,phase:2,chain,msg:'Potential SQL Injection'"
SecRule MATCHED_VAR "@rx (?:union\s+all.*?select)|(?:;\s*?select\s+.*?from)" \
    "t:none,t:lowercase"
```

The first rule uses fast `@pm` to check if any suspicious strings exist. Only if that passes does the more expensive regex check happen.

### 3. Use Selective Variable Targeting

Instead of:

```modsec
# Inefficient: Checks all variables 
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES "@pm admin root" \
    "id:10011,phase:2,deny"
```

Use:

```modsec
# Efficient: Only check where needed
SecRule ARGS_NAMES|REQUEST_COOKIES_NAMES "@pm admin root" \
    "id:10012,phase:2,deny"
```

Be precise about which variables need inspection.

### 4. Optimize Transformations

Transformations are processing steps applied to data before evaluation. They also have performance costs:

```modsec
# Inefficient: Multiple unnecessary transformations
SecRule REQUEST_URI "@rx admin" \
    "t:lowercase,t:urlDecode,t:htmlEntityDecode,t:removeWhitespace,t:compressWhitespace, \
     id:10013,phase:1,deny"
```

Only use what you need:

```modsec
# Efficient: Only necessary transformations
SecRule REQUEST_URI "@rx admin" "t:lowercase,t:urlDecode,id:10014,phase:1,deny"
```

### 5. Use Negative Security Model Where Appropriate

Positive security model (whitelist): Allow only what you know is good  
Negative security model (blacklist): Block what you know is bad

```modsec
# Highly efficient for limited access areas
SecRule REQUEST_METHOD "@rx ^(GET|HEAD)$" "chain,id:10015,phase:1"
SecRule REQUEST_URI "@beginsWith /api/public/" "chain"
SecRule &ARGS "@eq 0" "t:none,pass,nolog,skipAfter:END_PUBLIC_API"

# Any request reaching here doesn't match our whitelist
SecRule REQUEST_URI "@beginsWith /api/public/" "id:10016,phase:1,deny,status:403"

SecMarker END_PUBLIC_API
```

For public API endpoints that should only accept certain request methods with no parameters, this is far more efficient than checking for all possible attacks.

## Real-World Performance Optimization Example

Let's look at a real-world case study from a site I worked on. The site had a product catalog with thousands of items and a search feature that generated many false positives.

**Original Rule (Problematic):**

```modsec
# SQL Injection detection (part of default CRS)
SecRule ARGS "@rx select.*from" \
    "id:942100,phase:2,deny,msg:'SQL Injection'"
```

This was causing both false positives and performance issues.

**Optimized Approach:**

```modsec
# Step 1: Exclude search parameter from global SQL rules
SecRuleUpdateTargetById 942100 "!ARGS:search_query"

# Step 2: Add a targeted, more efficient rule for this parameter
SecRule ARGS:search_query "@pm select insert update delete union" \
    "id:10017,phase:2,chain,msg:'Potential SQL in search'"
SecRule MATCHED_VAR "@rx (?:\b(?:select|insert|update|delete)\b.{0,30}\b(?:from|into|where|table)\b)" \
    "t:none,t:lowercase,deny"
```

This optimization:
1. Removed the search parameter from global SQL injection checks
2. Created a fast first-pass check using `@pm`
3. Only ran the expensive regex when potentially suspicious content was found
4. Made the regex more precise to reduce false positives

The result?
- False positives dropped by 98%
- Average request processing time decreased by 42ms
- Server CPU load decreased by 19%

## Advanced Performance Techniques

For those managing high-traffic WAF deployments, here are some advanced techniques:

### 1. Use SecRuleRemoveById with Caution

```modsec
# Instead of completely removing rule
SecRuleRemoveById 942100

# Consider updating targets instead
SecRuleUpdateTargetById 942100 "!ARGS:harmless_field"
```

Complete rule removal makes your WAF less secure, targeted exclusions maintain security while improving performance.

### 2. Implement Request Rate Limiting

```modsec
# Track requests per IP
SecAction "id:10018,phase:1,pass,nolog,setvar:ip.connection_count=+1,expirevar:ip.connection_count=60"

# Block if too many
SecRule IP:CONNECTION_COUNT "@gt 100" "id:10019,phase:1,deny,status:429"
```

Rate limiting prevents resource exhaustion and DoS attacks.

### 3. Use SecCollectionTimeout for Garbage Collection

```modsec
# Set collection timeout to prevent memory bloat
SecCollectionTimeout 3600
```

This prevents memory usage from growing unbounded.

### 4. Employ SecStreamInBodyInspection for Large Files

```modsec
# Process large files in chunks
SecStreamInBodyInspection On
```

This allows ModSecurity to process large request bodies without loading them entirely into memory.

### 5. Benchmark and Profile Your Rules

One of the most valuable tools for WAF performance tuning is ModSecurity's debug log with timers:

```modsec
# Enable performance statistics
SecDebugLog /var/log/modsec_debug.log
SecDebugLogLevel 4
```

At level 4, ModSecurity logs performance data for each rule. Look for lines containing:
```
Performance: combined=1234(0), p1=5(0), p2=1229(0), p3=0(0), p4=0(0), p5=0(0)
```

These show execution time in microseconds for each phase. Rules taking more than a few hundred microseconds are candidates for optimization.

## Practical Performance Tuning Methodology

1. **Baseline**: Measure performance before making changes
2. **Identify**: Use debug logs to find slow rules
3. **Analyze**: Understand what makes these rules slow
4. **Optimize**: Apply the techniques covered above
5. **Measure**: Compare to baseline to confirm improvement
6. **Iterate**: Keep refining based on real-world performance

## Conclusion

WAF performance tuning is a balancing act between security and speed. By understanding the performance characteristics of different operators and applying targeted optimizations, you can achieve robust security without sacrificing user experience.

Remember that the fastest rule is the one you don't need to run. Be strategic about which rules run against which parts of the request, and leverage the performance hierarchy of operators whenever possible.

In the next post, we'll explore creating custom WAF rules for application-specific threats that aren't covered by standard rule sets. See you then!

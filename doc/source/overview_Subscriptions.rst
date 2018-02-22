-------------
Subscriptions
-------------

Rucio Subscriptions exist for the purpose of making data placement decisions before the actual data has been created.
Subscriptions generate rules for new datasets based on matching
metadata at registration time. Subscriptions are owned by an account and can
only generate rules for that account. Policies may have a lifetime, after which they will expire.

An example of a subscription is given below:

=========  ===================================================
Attribute  Value
=========  ===================================================
Owner      tzero
match      project=data11 7TeV, dataType=RAW, stream=physics*
rule       1\@CERNTAPE, 1\@T1TAPE
lifetime   2012-01-01 00:00
=========  ===================================================



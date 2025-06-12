# Query 1:

<DATA_STRUCTURE>

</DATA_STRUCTURE>

When I make an invoice the selling price must be taken from the product. 

==================

```js
invoice_line_set_price()
{
  if ( [invoice_line.invi_product] <>  null ) {
      query_single( "select prod_price from product where prod_code='"+[invoice_line.invi_product]+"'" );
      [invoice_line.invi_price] = [prod_price];
  } else {
      raise_error("Please select a product");
  }
}
```


# Query 2:

<DATA_STRUCTURE>

</DATA_STRUCTURE>
I need a button to create account for a contact person.
The fiscal code of the newly created account will be the contact persons SSN.
The name of the account will be the contact persons first and last name.
phone number and email address take from contact person.

==================

```js
contact_create_account(contact_id)
{
  [new_account] = null;
  query_single( "select cnt_fname,cnt_lname,cnt_ssn,cnt_phone,cnt_email from contact where cnt_id="+[contact_id] );
  /* verify existing account */
  If ( query_single( "select acc_code from account where acc_fiscal='"+[cnt_ssn]+"'" ) ) {
      raise_error("An Account with the same fisal number already exists");
  } else {
      [account.acc_code] = null;
      [account.acc_name] = [cnt_lname]+" "+[cnt_fname];
      [account.acc_fiscal] = [cnt_ssn];
      [account.acc_email] = [cnt_email];
      [account.acc_phone] = [cnt_phone];
      table_insert( "account" );
  }
  [new_account] = [account.acc_code];
}
```

# Query 3:

Sir, make me good code verify cnp please.

==================

```js
cnp_verify(cnp)
{
  if ( [cnp] == null || [cnp] == "" ) {
      raise_error("CNP cannot be empty");
  }
}
```
# ---+ Extensions
# ---++ LDAP Contrib
# ---+++ User settings

# **STRING**
# Comma-separated list of fields to search in when using autocomplete, i.e.
# urlparam-based %LDAP% queries (unless the autocomplete uses a custom list of
# fields using the 'urlparamfields' parameter).
$Foswiki::cfg{Ldap}{DefaultAutocompleteFields} = 'sn,givenName,sAMAccountName';


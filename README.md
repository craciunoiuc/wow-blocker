# WoW Login Faker
Simple web server that blocks access to one account, but forwards the rest.
This can be used as a prank to spook people into thinking they have been banned.

Only tested with World of Warcraft 3.3.5a (WotLK) client.

The server sends 4 responses that trigger an "Unknown Account" similar to the one you get when inputting a wrong username/password.
The fifth response is an "Account Permanently Suspended" response that blocks the account from logging in.
This does not affect other accounts, and the whole login process is faked, as such nothing is really altered.

## Usage

1. Clone the repository and navigate to the directory.
2. Replace in `server.py` the `TESTINGACCOUNT` with the account you want to block. Also replace `realm_list` with the realm you want to forward traffic to.
2. Run the server with `python3 server.py`.
3. Set in *your* local WoW directory the `realmlist.wtf` file the realmlist to point to this server.
3.'  Or set in *your* hosts file to redirect the realmlist original server to this one.
3.'' Any other known method to redirect traffic from port 3724 to this server will work.
4. Start the WoW client and try to log in with the account you want to block.

## Known Issues

After getting the "Account Permanently Suspended" response, the client will no longer work properly and it will be necessary to restart it.

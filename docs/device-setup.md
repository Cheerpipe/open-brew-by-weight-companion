# Device setup

Each phone, tablet or computer needs to trust the companion's certificate once.
The easiest way is the setup page: open **`http://openbrewbyweight-secure.local`**
(plain `http`) on the device, or scan the QR code that `./setup` shows or
that the page shows on a computer. It shows whether the device already
trusts the companion, opens the steps for that device, and offers the right
download. The page is in Spanish when the device's language is Spanish, and
in English otherwise. Opened on a computer, the iPhone and Android steps also
show a QR code that downloads the file straight onto the phone.

The steps below are the same as on that page, for reference. If you changed
`COMPANION_HOSTNAME`, use your name instead of `openbrewbyweight-secure`.

## iPhone and iPad

1. Open the setup page in **Safari** and tap **Download the profile**. Choose
   **Allow**.
2. Open **Settings**, tap **Profile Downloaded** near the top, then
   **Install**.
3. Go to **Settings → General → About → Certificate Trust Settings** and switch
   on **Open Brew by Weight local CA**. iOS does not trust an installed
   certificate until you do this.
4. Open `https://openbrewbyweight-secure.local` and add it to your Home Screen
   if you like.

To remove it later: **Settings → General → VPN & Device Management**.

## Mac

1. Download the certificate from the setup page and double-click it. Keychain
   Access opens; add it to the **login** keychain.
2. Double-click **Open Brew by Weight local CA**, open **Trust**, and set
   **When using this certificate** to **Always Trust**. Close the window and
   confirm with your password.
3. Restart your browser and open `https://openbrewbyweight-secure.local`.

To remove it later, delete the certificate in Keychain Access.

## Windows

1. Download the certificate from the setup page and open it.
2. Choose **Install Certificate…**, then **Current User**.
3. Choose **Place all certificates in the following store**, then
   **Browse…**, and select **Trusted Root Certification Authorities**. Finish
   and answer **Yes** to the security warning.
4. Restart your browser and open `https://openbrewbyweight-secure.local`.

To remove it later, run `certmgr.msc` and delete it from Trusted Root
Certification Authorities.

## Android

1. Download the certificate from the setup page in Chrome.
2. Open **Settings** and search for **CA certificate**. It is usually under
   **Security → More security settings → Encryption & credentials → Install a
   certificate → CA certificate**; the path varies by manufacturer.
3. Tap **Install anyway** and pick the downloaded file. Android may ask you to
   set a screen lock first.
4. Open `https://openbrewbyweight-secure.local` in Chrome.

Android 12 or newer is needed to open `.local` addresses. To remove the
certificate later, open **Trusted credentials → User**.

## Firefox

Firefox keeps its own certificate list on some systems. If it still shows a
warning after the steps above, import the certificate under **Settings →
Privacy & Security → View Certificates → Authorities** and trust it for
websites. On Android, Firefox also needs **Use third-party CA certificates**
switched on in its secret settings.

## Check the download

The setup page shows the certificate's SHA-256 fingerprint. Your device shows
the same fingerprint in the certificate's details; if they differ, do not
install it.

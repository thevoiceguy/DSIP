# DSIP: What Is It and Why Do We Need It?

DSIP enables direct, secure communication without relying on traditional phone companies.

Today, carriers sit in the middle of every call, assigning numbers, controlling access, and logging metadata. Lumen announced that they will no longer sell net new voice services, and when your current contract is up, they will move you to a month-to-month plan, and we all know what happens then.  Your service triples in cost as a way for them to move you off their platform. In short, Lumen, a Tier 1 carrier, is exiting the phone business.  How long before others follow the same path?

DSIP asks: What if none of that was needed?

## How It Works

### You Are Your Key
Instead of a phone number, you generate a cryptographic key pair. The public half becomes your permanent identity (your "DID"), which you share via QR code, link, or custom domain.

### Your Devices Speak for You
Phones and laptops get individual device keys authorized by your master DID. Losing or replacing a device requires only revoking its specific key; your primary identity remains intact.

### You Pick a Relay
Because mobile devices frequently change networks, they maintain an outbound connection to a fixed relay server (self-hosted, shared, or commercial). Relays forward encrypted signaling frames but cannot forge messages or access content. You can run one yourself on a cheap box, join a friend's, or use one somebody hosts. A company can host their own relay.  The relay can deliver messages to you, but it can't pretend to be you, because it doesn't have your key.

### You Publish Your Location
Devices write signed, time-limited reachability hints ("DID X is currently at Relay Y") to a Distributed Hash Table (DHT). Unrefreshed entries auto-expire when devices go offline.

### Discovery Happens Directly
To reach you, a contact queries the DHT using your DID to retrieve your signed location hint. The lookup network cannot search users or expose directory listings to strangers.

### The Call Setup
Your friend connects to your relay, proves who they are with a signed hello, and sends a signed invite. The relay rings every device you have bound. One answers; the relay hangs up the rest. Every message is signed by the sender, so the relay can only pass things along or drop them; it can never change them

### Direct Encrypted Audio
Signaling payload exchanges facilitate a direct, peer-to-peer encrypted media stream between endpoints (using WebRTC/ICE standards), bypassing relay infrastructure entirely.

### Seamless Mobility
Switching networks (e.g., Wi-Fi to cellular) re-establishes the connection to your relay while keeping the routing hint valid. Migrating relays updates the DHT entry via an incremented sequence number.

## Beyond Phone Calls

DSIP acts as a universal real-time communication fabric connecting humans, AI agents, and autonomous hardware across a shared cryptographic identity layer:

* **Human-to-AI:** Place direct, end-to-end encrypted voice calls to AI agents using their unique DIDs without passing media through proprietary app platforms.
* **Machine-to-Machine:** A smart TV assigned a DID can subscribe directly to a team's live broadcast channel with zero central proxy overhead.

## Why It Matters

Your identity remains strictly under your control, communication content remains encrypted end-to-end, and the routing lookup operates without a central point of failure. Legacy phone network connectivity is maintained via translation gateways that map numbers to DIDs.

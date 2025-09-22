# A digital signature is a mathematical technique used to validate the authenticity and
# integrity of a digital message. A digital signature is the equivalent of a handwritten
# signature. Digital signatures can actually be far more secure. The purpose of a digital
# signature is to prevent the tampering and impersonation in digital communications.
# Using Digital Signatures
# In this part, you will use a website to verify a document signature between Alice and
# Bob. Alice and Bob share a pair of private and public RSA keys. Each of them uses their
# private key to sign a legal document. They then send the documents to each other. Both
# Alice and Bob can verify each other’s signature with the public key. They must also
# agree on a shared public exponent for calculation

# Step 1: Sign the Document.
# Alice signs a legal document and send it to Bob using the RSA public and private keys
# shown in the table 1. Now Bob will have to verify Alice’s digital signature in order to
# trust the authenticity of the electronic document.
# Step 2: Verify Digital Signature.
# Bob receives the document with a digital signature shown in the table below. Table 2 – Alice’s Digital Signature

# a. Copy and paste the public and private keys from Table 1 above into the Public
# Modulus and Private Exponent boxes on the website as shown in the Figure 6.1.
# b. Make sure the Public Exponent is 10001.
# c. Paste Alice’s digital signature from Table 2 in the box labeled text on the website as
# shown.
# d. Now BOB can verify the digital signature by clicking the Verify button near the
# bottom center of the website. Whose signature is identified?
# Alice’s name should be displayed.
# Step 3: Generate a Response Signature.
# Bob receives and verifies Alice’s electronic document and digital signature. Now Bob
# creates an electronic document and generates his own digital signature using the private
# RSA Key in Table 1 (Note: Bob’s name is in all capital letters).
# Figure 6.1 Online Digital Signature Tool
# Table 4 – BOB Digital Signature
# Bob sends the electronic document and digital signature to Alice.
# Step 4: Verify Digital Signature.
# a. Copy and paste the public and private keys from Table 1 above into the Public
# Modulus and Private Exponent boxes on the website as shown in the picture above.
# b. Make sure the Public Exponent is 10001.
# c. Paste Bob’s digital signature from Table 4 in the box labeled text on the website as
# shown above.
# d. Now Alice can verify the digital signature by clicking the Verify button near the
# bottom center of the website. Whose signature is identified?
# Bob’s name should be displayed.
# Part 2: Create Your Own Digital Signature
# Now that you see how digital signatures work, you can create your own digital signature.
# Step 1: Generate a New Pair of RSA Keys.
# Go to the website tool and generate a new set of RSA public and private keys.
# a. Delete the contents of the boxes labeled Public Modulus, Private Modulus and Text.
# Just use your mouse to highlight the text and press the delete key on your keyboard.
# b. Make sure the “Public Exponent” box has 10001.
# c. Generate a new set of RSA keys by clicking the Generate button near the bottom right
# of the website.
# d. Copy the new keys in Table 5.
# e. Now type in your full name into the box labeled Text and click Sign.
# Part 3: Exchange and Verify Digital Signatures
# Now you can use this digital signature.
# Step 1: Exchange your new public and private keys in Table-5 with your lab partner.
# a. Record your lab partner’s public and private RSA keys from their Table-5.
# b. Record both keys in the table below
# Now exchange their digital signature from their Table-6. Record the digital signature in
# the table below
# Step 2: Verify Lab Partners Digital Signature
# a. To verify your lab partner’s digital signature, paste his or her public and private keys
# in the appropriate boxes labeled Public and Private modulus on the website.
# b. Now paste the digital signature in the box labeled Text.
# c. Now verify his or her digital signature by clicking the button labeled verify.
# d. What shows up in the Text box?
# Answers will vary.
# Lab Exercises
# 1. Try using the Elgammal, Schnor asymmetric encryption standard and verify the above
# steps.
# 2. Try using the Diffie-Hellman asymmetric encryption standard and verify the above
# steps.
# 3. Try the same in a client server-based scenario and record your observation and
# analysis.
# Additional Exercise
# 1. Explore the link https://www.nmichaels.org/rsa.py for better understanding.
# Demonstrate CIA traid using RSA encryption and digital signature along with SHA
# hashing



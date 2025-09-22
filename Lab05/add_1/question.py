# Write server and client scripts where the client sends a message in multiple parts to
# the server, the server reassembles the message, computes the hash of the reassembled
# message, and sends this hash back to the client. The client then verifies the integrity of
# the message by comparing the received hash with the locally computed hash of the
# original message
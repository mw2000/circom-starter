// Include the necessary files
include "commitment-hasher.circom";
include "merkle-tree.circom";

// The Withdraw template verifies that a commitment, which corresponds to a given secret and nullifier, 
// is included in the Merkle tree of deposits.
template Withdraw(levels) {
    // Inputs for the template
    signal input root; // The root of the Merkle tree
    signal input nullifierHash; // The hash of the nullifier
    signal input recipient; // The recipient of the withdrawal. This does not take part in any computations
    signal input relayer;  // The relayer of the withdrawal. This does not take part in any computations
    signal input fee;      // The fee for the withdrawal. This does not take part in any computations
    signal input refund;   // The refund for the withdrawal. This does not take part in any computations

    signal input nullifier; // The nullifier of the withdrawal
    signal input secret; // The secret of the withdrawal
    signal input pathElements[levels]; // The path elements of the Merkle tree
    signal input pathIndices[levels]; // The path indices of the Merkle tree

    // Create a CommitmentHasher component
    component hasher = CommitmentHasher();
    hasher.nullifier <== nullifier; // Set the nullifier of the hasher
    hasher.secret <== secret; // Set the secret of the hasher
    hasher.nullifierHash === nullifierHash; // Ensure the nullifier hash of the hasher is the same as the input nullifier hash

    // Create a MerkleTreeChecker component
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== hasher.commitment; // Set the leaf of the tree to the commitment of the hasher
    tree.root <== root; // Set the root of the tree to the input root
    // Loop through each level of the tree
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i]; // Set the path element of the tree at this level to the corresponding input path element
        tree.pathIndices[i] <== pathIndices[i]; // Set the path index of the tree at this level to the corresponding input path index
    }

    // Add hidden signals to make sure that tampering with recipient or fee will invalidate the snark proof
    // Squares are used to prevent optimizer from removing these constraints
    signal recipientSquare;
    signal feeSquare;
    signal relayerSquare;
    signal refundSquare;
    recipientSquare <== recipient * recipient; // Square the recipient
    feeSquare <== fee * fee; // Square the fee
    relayerSquare <== relayer * relayer; // Square the relayer
    refundSquare <== refund * refund; // Square the refund
}

component main = Withdraw(20);

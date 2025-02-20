# Function Documentation

Below is an overview of the functions implemented:

## 1. `main`
- **Input:**  
  None
- **Output:**  
  None
- **Description:**  
  This function initializes the mcl library using the **bls12-381** elliptic curve and executes the `slicingVCS` function.

---

## 2. `extractValue`
- **Input:**  
  - `aFr []mcl.Fr`: A state vector used for verification and updates.  
  - `index uint64`: The index of an element in the vector.
- **Output:**  
  None
- **Description:**  
  This function uses bit manipulation to extract and print the **value** of a vector element.

---

## 3. `extractNonce`
- **Input:**  
  - `aFr []mcl.Fr`: A state vector used for verification and updates.  
  - `index uint64`: The index of an element in the vector.
- **Output:**  
  None
- **Description:**  
  This function uses bit manipulation to extract and print the **nonce** of a vector element.

---

## 4. `slicingVCS`
- **Input:**  
  - `L uint8`: The number of levels of VCS, used for calculating the size of the vector.  
  - `txnLimit uint64`: The number of transactions.
- **Output:**  
  None
- **Description:**  
  This function implements state verification and updates. Its workflow can be divided into the following parts:
  
  1. **Initialization:**  
     - Define `N`: the size of the vector.  
     - Define `K`: the number of transactions.  
     - Initialize `vcs`, generate keys, and create four vectors.
  
  2. **Generate the Initial State:**  
     - Compute `aFr` (state vector), `digest`, and proofs for all the elements in the vector.
  
  3. **Randomly Generate Updates:**  
     - Randomly generate the modified indices and the corresponding change amounts.
  
  4. **Verification (Pre-update):**  
     - Use `Verify` and `VerifyMemoized` to verify the initial state.
  
  5. **Apply Updates:**  
     - Use `UpdateProofTree` and `SecondaryStateUpdate` to apply changes to the proof tree and `valueVec`.
  
  6. **Post-update Verification:**  
     - Retrieve the updated `proofVec` and `digest`, then use `VerifyMemoized` to verify the updated state.
  
  7. **Bulk Update and Verification:**  
     - Apply `UpdateProofTreeBulk` and use `VerifyMemoized` to verify the updates.

---

## 5. `SecondaryStateUpdate`
- **Input:**  
  - `indexVec []uint64`: A vector containing the indices of modified elements.  
  - `deltaVec []mcl.Fr`: A vector containing the change amounts for the corresponding indices.  
  - `valueVec []mcl.Fr`: A vector containing the current values of the modified indices.
- **Output:**  
  - `[]mcl.Fr`: The updated vector after applying the changes.
- **Description:**  
  This function updates the vector stored in mcl by:
  - Mapping the current values from `valueVec` to their respective indices.
  - Accumulating changes from `deltaVec` (even handling duplicates by summing changes).
  - Applying the cumulative changes to the corresponding elements in the state vector.
  - Returning the updated state vector.

---

## 6. `BenchmarkVCSCommit`
- **Input:**  
  - `L uint8`: The number of levels for VCS, used to calculate the vector size \(N = 2^L\).  
  - `txnLimit uint64`: The number of transactions.
- **Output:**  
  - `string`: A formatted benchmark result string indicating the commit operation's execution time.
- **Description:**  
  This function benchmarks the commit operation of the VCS system by:
  1. Initializing a VCS instance with the given key parameters and transaction limit.
  2. Generating a vector `aFr` of size \(N\) using the provided level \(L\).
  3. Saving the generated vector via `SaveVector`.
  4. Measuring the time taken by the `Commit` operation on the vector.
  5. Formatting the benchmark result into a string including details such as `L`, `txnLimit`, and the operation duration.
  6. Returning the formatted benchmark result string.

---

## 7. `hyperGenerateKeys`
- **Input:**  
  - `L uint8`: The level parameter used to determine the vector size \(N = 2^L\) and set key generation parameters.
  - `fake bool`: A boolean flag (it is not used within the function's logic).
- **Output:**  
  - `*vcs.VCS`: A pointer to a VCS structure that contains the generated keys.
- **Description:**  
  This function generates keys for the VCS system.

---

## 8. `hyperLoadKeys`
- **Input:**  
  - `L uint8`: The level parameter used to determine the folder path from which the keys will be loaded.
- **Output:**  
  - `*vcs.VCS`: A pointer to a VCS structure that contains the loaded keys.
- **Description:**  
  This function loads previously generated keys for the VCS system.

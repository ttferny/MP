exports.parseHeader = (header) => { // [1] Exported parser uses [2]-[6].
  const lines = header.split("\n"); // [2] Split header into lines for [5].

  let from = ""; // [3] Init from value filled in [5a].
  let returnPath = ""; // [4] Init return-path filled in [5b].
  let dkimSignature = ""; // [5] Init DKIM signature filled in [5c].

  lines.forEach(line => { // [5d] Walk each line from [2].
    if (line.toLowerCase().startsWith("from:")) { // [5a] Detect from line to set [3].
      from = line.split(":")[1].trim(); // [5a1] Parse from value for [3].
    }
    if (line.toLowerCase().startsWith("return-path:")) { // [5b] Detect return-path to set [4].
      returnPath = line.split(":")[1].trim(); // [5b1] Parse return-path value for [4].
    }
    if (line.toLowerCase().startsWith("dkim-signature:")) { // [5c] Detect DKIM signature to set [5].
      dkimSignature = line; // [5c1] Store full signature line for [5].
    }
  });

  return { from, returnPath, dkimSignature }; // [6] Return parsed values from [3]-[5].
};
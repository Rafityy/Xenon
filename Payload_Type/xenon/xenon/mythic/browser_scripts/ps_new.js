function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { 'plaintext': combined };
    } else if (responses.length > 0) {
        // Combine and split the responses into lines
        const output = responses.reduce((prev, cur) => prev + cur, "").split("\n").filter(line => line.trim() !== "");
        if (output.length === 0) {
            return { 'plaintext': "No process information found." };
        }

        // Prepare the table structure
        const formattedResponse = {
            headers: [
                { plaintext: "Process Name", type: "string", fillWidth: true },
                { plaintext: "PPID", type: "number", width: 80 },
                { plaintext: "PID", type: "number", width: 80 },
                { plaintext: "Architecture", type: "string", width: 80 },
                { plaintext: "User Account", type: "string", fillWidth: true },
                { plaintext: "Session ID", type: "number", width: 80 }
            ],
            title: "Process List",
            rows: []
        };

        // Process each line to populate rows
        output.forEach(line => {
            const parts = line.split("\t");
            // Ensure the array has up to 6 elements, filling missing parts with empty strings
            while (parts.length < 6) {
                parts.push("");
            }
            const [processName, ppid, pid, architecture, userAccount, sessionId] = parts;

            // Add the row, ensuring missing fields are shown as empty cells
            formattedResponse.rows.push({
                "Process Name": {
                    plaintext: processName || "",
                    cellStyle: {}
                },
                "PPID": {
                    plaintext: ppid || "",
                    cellStyle: {}
                },
                "PID": {
                    plaintext: pid || "",
                    cellStyle: {}
                },
                "Architecture": {
                    plaintext: architecture || "",
                    cellStyle: {}
                },
                "User Account": {
                    plaintext: userAccount || "",
                    cellStyle: {}
                },
                "Session ID": {
                    plaintext: sessionId || "",
                    cellStyle: {}
                }
            });
        });

        return { table: [formattedResponse] };
    } else {
        return { 'plaintext': "No response yet from agent..." };
    }
}

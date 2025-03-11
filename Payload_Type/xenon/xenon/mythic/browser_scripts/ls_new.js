function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { 'plaintext': combined };
    } else if (responses.length > 0) {
        // Parse the output data
        const output = responses.reduce((prev, cur) => prev + cur, "").split("\n").filter(line => line.trim() !== "");
        if (output.length <= 2) {
            return { 'plaintext': "No directory contents found." };
        }

        // Extract path and rows
        const pathLine = output[1];
        const dataLines = output.slice(2);

        // Prepare the table structure
        const formattedResponse = {
            headers: [
                { plaintext: "Type", type: "string", width: 60, disableSort: true },
                { plaintext: "Size", type: "string", width: 80, disableSort: true },
                { plaintext: "Date Modified", type: "string", fillWidth: true },
                { plaintext: "Name", type: "string", fillWidth: true }
            ],
            title: `Contents of ${pathLine}`,
            rows: []
        };

        // Format rows for table
        dataLines.forEach(line => {
            const parts = line.split("\t");
            if (parts.length === 4) {
                const [type, size, modified, name] = parts;
                formattedResponse.rows.push({
                    Type: {
                        plaintext: type === "D" ? "Directory" : "File",
                        cellStyle: {},
                    },
                    Size: {
                        plaintext: type === "D" ? "-" : size + " bytes",
                        cellStyle: {},
                    },
                    "Date Modified": {
                        plaintext: modified,
                        cellStyle: {},
                    },
                    Name: {
                        plaintext: name,
                        cellStyle: {},
                    }
                });
            }
        });

        return { table: [formattedResponse] };
    } else {
        return { 'plaintext': "No response yet from agent..." };
    }
}

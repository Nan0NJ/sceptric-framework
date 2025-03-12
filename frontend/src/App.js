import React, { useState } from 'react';

function App() {
    const [result, setResult] = useState('');
    const [loading, setLoading] = useState(false);

    const handleStartClick = async () => {
        setLoading(true);
        try {
            const response = await fetch('http://localhost:8080/api/start');
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            const data = await response.text();
            setResult(data);
        } catch (error) {
            setResult('Error: ' + error.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            <h1>Sceptric Framework</h1>
            <button onClick={handleStartClick} disabled={loading}>
                {loading ? 'Running...' : 'Start Evaluation'}
            </button>
            {result && (
                <div style={{ marginTop: '20px' }}>
                    <h2>Result:</h2>
                    <pre>{result}</pre>
                </div>
            )}
        </div>
    );
}

export default App;
const button = document.getElementById('check-button');
const input = document.getElementById('domain-input');
const result = document.getElementById('result');

button.addEventListener('click', async () => {
  const domain = input.value.trim();

  if (!domain) {
    result.textContent = 'Please enter a domain.';
    return;
  }

  result.textContent = 'Checking...';
  button.disabled = true;

  try {
    const response = await fetch(`/check?domain=${encodeURIComponent(domain)}`);
    const data = await response.json();

    if (!response.ok) {
      result.textContent = data.error || 'Something went wrong.';
      return;
    }

    renderResult(data);
  } catch (err) {
    result.textContent = 'Could not reach the server. Is it running?';
  } finally {
    button.disabled = false;
  }
});

function renderResult(data) {
  const lines = [];

  lines.push(`Score: ${data.score} / 100`);
  lines.push('');
  lines.push(`SPF: ${data.spf.found ? 'Found' : 'Not found'}`);
  lines.push(`DKIM: ${data.dkim.found ? `Found (selector: ${data.dkim.selector})` : 'Not found among common selectors'}`);
  lines.push(`DMARC: ${data.dmarc.found ? `Found (policy: ${data.dmarc.policy || 'none specified'})` : 'Not found'}`);
  lines.push('');
  lines.push('Recommendations:');
  data.recommendations.forEach(rec => lines.push(`- ${rec}`));

  result.textContent = lines.join('\n');
}

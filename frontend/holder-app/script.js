// Basic viewer/presenter for credentials
let credentials = [];
let selectedIndex = null;

function loadCredentials() {
  const holderDid = document.getElementById('holderDid').value;
  const password = document.getElementById('password').value;
  fetch('/holder/credentials', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ holder_did: holderDid, password })
  })
    .then(r => r.json())
    .then(data => {
      credentials = data.credentials || [];
      const list = document.getElementById('credList');
      list.innerHTML = '';
      credentials.forEach((_, idx) => {
        const li = document.createElement('li');
        li.textContent = `Credencial ${idx} `;
        const btnSel = document.createElement('button');
        btnSel.textContent = 'Seleccionar';
        btnSel.onclick = () => selectCredential(idx);
        const btnDet = document.createElement('button');
        btnDet.textContent = 'Detalles';
        btnDet.onclick = () => viewDetails(idx);
        li.appendChild(btnSel);
        li.appendChild(btnDet);
        list.appendChild(li);
      });
    });
}

function selectCredential(i) {
  selectedIndex = i;
  document.getElementById('selected').textContent = 'Seleccionada credencial ' + i;
  viewDetails(i);
}

function viewDetails(i) {
  const holderDid = document.getElementById('holderDid').value;
  const password = document.getElementById('password').value;
  fetch('/holder/decode-credential', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ holder_did: holderDid, password, index: i })
  })
    .then(r => r.json())
    .then(data => {
      document.getElementById('details').textContent = JSON.stringify(data, null, 2);
    });
}

function present() {
  if (selectedIndex === null) {
    alert('Seleccione una credencial');
    return;
  }
  const holderDid = document.getElementById('holderDid').value;
  const password = document.getElementById('password').value;
  const aud = document.getElementById('aud').value || 'openid://';
  const nonce = document.getElementById('nonce').value || crypto.randomUUID();
  const send = document.getElementById('send').checked;
  fetch('/wallet/present', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      holder_did: holderDid,
      password,
      select: [selectedIndex],
      aud,
      nonce,
      send
    })
  })
    .then(r => r.json())
    .then(data => {
      document.getElementById('vpjwt').textContent = data.vp_jwt || '';
      if (send) {
        document.getElementById('postresult').textContent = 'POST status: ' + data.post_status;
      } else {
        document.getElementById('postresult').textContent = '';
      }
    });
}

<script>
	import IconBadge from "../icons/IconBadge.svelte";

    // export let cert = {};
    export let cert = {
		issuer: "CN=Nioca Root, O=NetIT-Services, CN=Nioca Root, O=NetIT-Services, CN=Nioca Root, O=NetIT-Services",
		serial: 64,
		subject: "CN=Nioca Root, O=NetIT-Services",
		validity: {
			notBefore: "May 12 01:57:36 2021 +00:00",
			notAfter: "Feb  1 12:32:36 2053 +00:00"
		},
		version: "V3",
		signatureAlg: "1.2.840.10045.4.3.3",
		isCa: true,
		keyUsages: {
			critical: true,
			value: ["Digital Signature, Key Cert Sign, CRL Sign"],
		}
	};
</script>

<div class="cert">
  <div class="block row">
    <div class="label">
      Issuer
    </div>
    <div class="value">
      {cert.issuer}
    </div>
  </div>

  <div class="block row">
    <div class="label">
      Serial
    </div>
    <div class="value">
      {cert.serial}
    </div>
  </div>

  <div class="block row">
    <div class="label">
      Subject
    </div>
    <div class="value">
      {cert.subject}
    </div>
  </div>

  <div class="block">
    <div class="label">
      Validity
    </div>

    <div class="row nested">
      <div class="labelNested">
        Not Before
      </div>
      <div class="value">
        {cert.validity.notBefore}
      </div>
    </div>

    <div class="row nested">
      <div class="labelNested">
        Not After
      </div>
      <div class="value">
        {cert.validity.notAfter}
      </div>
    </div>
  </div>

  <div class="block row">
    <div class="label">
      Version
    </div>
    <div class="value">
      {cert.version}
    </div>
  </div>

  <div class="block row">
    <div class="label">
      Signature Alg
    </div>
    <div class="value">
      {cert.signatureAlg}
    </div>
  </div>

  <div class="block row">
    <div class="label">
      Is CA
    </div>
    <div class="value">
      {cert.isCa}
    </div>
  </div>

  <div class="block">
    <div class="label">
      Key Usages
    </div>

    <div class="row nested">
      <div class="labelNested">
        Critical
      </div>
      <div class="value">
        {cert.keyUsages.critical}
      </div>
    </div>

    <div class="row nested">
      <div class="labelNested">
        Value
      </div>
      <div class="value">
        {cert.validity.notAfter}
      </div>
    </div>
  </div>

  <div class="badgeWrapper">
    <div class="badge">
      <IconBadge width={64} opacity={0.5} color="var(--col-ok)" />
    </div>
  </div>

</div>

<style>
    .badgeWrapper {
      position: relative;
    }

    .badge {
        position: absolute;
        bottom: 0;
        right: 0;
    }

    .block {
        margin: 5px 0;
    }

    .cert {
        padding: 10px;
        border: 3px solid var(--col-gmid);
        border-radius: 10px;
    }

    .label {
        width: 120px;
        font-weight: bold;
    }

    .labelNested {
        width: 110px;
        font-weight: bold;
    }

    .nested {
        margin-left: 10px;
    }

    .value {
        max-width: 340px;
    }

    .row {
        display: flex;
    }
</style>

<script>
    import {OPT_X509_KEY_ALG, X509_KEY_USAGES_EXT_SSO, X509_KEY_USAGES_SSO} from "../../../../utils/constants.js";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import Input from "$lib/inputs/Input.svelte";
    import Switch from "$lib/Switch.svelte";
    import SwitchList from "$lib/SwitchList.svelte";

    export let accessX509;
    export let formErrors;

    let keyUsages = X509_KEY_USAGES_SSO.map(f => {
        f.value = accessX509.keyUsage?.includes(f.label);
        return f;
    });

    let keyUsagesExt = X509_KEY_USAGES_EXT_SSO.map(f => {
        f.value = accessX509.keyUsageExt?.includes(f.label);
        return f;
    });

    export function getKeyUsages() {
        return keyUsages.filter(f => f.value).map(f => f.label);
    }

    export function getKeyUsagesExt() {
        return keyUsagesExt.filter(f => f.value).map(f => f.label);
    }

</script>

<!-- Enabled -->
<div class="data row" style="margin-bottom: 10px">
    <div class="label switchLabel">
        Enabled
    </div>
    <div class="value">
        <Switch bind:selected={accessX509.enabled}/>
    </div>
</div>

<!-- Valid Hours -->
<div class="data">
    <Input
            name="validHours"
            bind:value={accessX509.validHours}
            bind:error={formErrors.validHours}
            placeholder="Certificate validity in hours"
    >
        VALID FOR HOURS
    </Input>
</div>

<div class="data">
    <div class="label">
        Key Algorithm
    </div>
    <OptionSelect
            bind:value={accessX509.keyAlg}
            options={OPT_X509_KEY_ALG}
    />
</div>

<div class="data">
    <div class="label">
        X509 Key Usages
    </div>
    <div class="value">
        <SwitchList bind:options={keyUsages} labelWidth="10rem"/>
    </div>
</div>

<!-- Key Usages Ext -->
<div class="data">
    <div class="label">
        X509 Key Usages Extended
    </div>
    <div class="value">
        <SwitchList bind:options={keyUsagesExt} labelWidth="10rem"/>
    </div>
</div>

<style>
    .label {
        min-height: 30px;
        margin: 0 5px;
        padding-top: 5px;
        display: flex;
    }

    .row {
        display: flex;
        align-items: center;
    }

    .switchLabel {
        width: 10rem;
    }

    .value {
        display: flex;
        align-items: center;
    }
</style>

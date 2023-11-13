<script>
    import {REGEX_LINUX_USER, SSH_CERT_AGLS} from "../../../../utils/constants.js";
    import Switch from "$lib/Switch.svelte";
    import ExpandableInputs from "$lib/expandableInputs/ExpandableInputs.svelte";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import Input from "$lib/inputs/Input.svelte";

    export let accessSsh;
    export let formErrors;
    export let validatePrincipals;

</script>

<!-- Enabled -->
<div class="data row" style="margin-bottom: 10px">
    <div class="label" style:width="8.25rem">
        Enabled
    </div>
    <div class="value">
        <Switch bind:selected={accessSsh.enabled}/>
    </div>
</div>

<!-- Valid Secs -->
<div class="data">
    <Input
            name="validSecs"
            bind:value={accessSsh.validSecs}
            bind:error={formErrors.validSecs}
            placeholder="Valid for Seconds"
    >
        VALID FOR SECONDS
    </Input>
</div>

<!-- Key Alg -->
<div class="data">
    <div class="label">
        Key Algorithm
    </div>
    <OptionSelect
            options={SSH_CERT_AGLS}
            bind:value={accessSsh.keyAlg}
    />
</div>

<div class="separator">
</div>

<!-- Principals -->
<div class="desc">
    The principals must match exising usernames on the target system.
</div>
<div class="data">
    <ExpandableInputs
            validation={{
                                required: false,
                                regex: REGEX_LINUX_USER,
                                errMsg: "Valid characters: [a-z0-9-_@.]{2,30}",
                            }}
            bind:values={accessSsh.principals}
            bind:validate={validatePrincipals}
            autocomplete="off"
            placeholder="Valid Principal"
    >
        VALID PRINCIPAL
    </ExpandableInputs>
</div>

<!-- Permits -->
<div class="data">
    <div class="flex">
        <div class="label switchLabel">
            X11 Forwarding
        </div>
        <div class="value">
            <Switch bind:selected={accessSsh.permitX11Forwarding}/>
        </div>
    </div>
</div>

<div class="data">
    <div class="flex">
        <div class="label switchLabel">
            Agent Forwarding
        </div>
        <div class="value">
            <Switch bind:selected={accessSsh.permitAgentForwarding}/>
        </div>
    </div>
</div>

<div class="data">
    <div class="flex">
        <div class="label switchLabel">
            Port Forwarding
        </div>
        <div class="value">
            <Switch bind:selected={accessSsh.permitPortForwarding}/>
        </div>
    </div>
</div>

<div class="data">
    <div class="flex">
        <div class="label switchLabel">
            PTY
        </div>
        <div class="value">
            <Switch bind:selected={accessSsh.permitPty}/>
        </div>
    </div>
</div>

<div class="data">
    <div class="flex">
        <div class="label switchLabel">
            User RC
        </div>
        <div class="value">
            <Switch bind:selected={accessSsh.permitUserRc}/>
        </div>
    </div>
</div>

<style>
    .desc {
        margin: 1rem 0;
    }

    .flex {
        display: flex;
        align-items: center;
    }

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

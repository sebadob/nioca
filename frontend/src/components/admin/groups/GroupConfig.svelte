<script>
    import * as yup from "yup";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import Switch from "$lib/Switch.svelte";
    import Button from "$lib/Button.svelte";
    import {onMount} from "svelte";
    import {REGEX_CA_NAME} from "../../../utils/constants.js";
    import Input from "$lib/inputs/Input.svelte";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import {fetchPutGroups} from "../../../utils/dataFetching.js";

    export let casSsh = [];
    export let casX509 = [];
    export let group = {};
    export let onSave;

    let width = '23rem';
    let err = '';
    let success = false;
    let timer;

    function fmtCaName(ca) {
        if (ca.validity?.notAfter) {
            return `${ca.name} - not after: ${ca.validity.notAfter}`;
        } else {
            return ca.name;
        }
    }

    function caSshIdByName(name) {
        for (let ca of casSsh) {
            if (ca.name === name) {
                return ca.id;
            }
        }
    }

    function caSshNameById(id) {
        for (let ca of casSsh) {
            if (ca.id === id) {
                return fmtCaName(ca);
            }
        }
    }

    let caSshName = caSshNameById(group.caSsh);
    const caSshOptions = casSsh.map(ca => fmtCaName(ca));

    function caX509IdByName(name) {
        for (let ca of casX509) {
            if (fmtCaName(ca) === name) {
                return ca.id;
            }
        }
    }

    function caX509NameById(id) {
        for (let ca of casX509) {
            if (ca.id === id) {
                return fmtCaName(ca);
            }
        }
    }

    let caX509Name = caX509NameById(group.caX509);
    const caX509Options = casX509.map(ca => fmtCaName(ca));

    $: if (success) {
        timer = setTimeout(() => {
            success = false;
            onSave();
        }, 3000);
    }

    onMount(() => {
        return () => clearTimeout(timer);
    });

    let formErrors = {};

    const schema = yup.object().shape({
        name: yup.string().required('Required').trim().matches(REGEX_CA_NAME, "Invalid Characters"),
    });

    function handleKeyPress(event) {
        if (event.code === 'Enter') {
            onSubmit();
        }
    }

    async function onSubmit() {
        err = '';

        const valid = await validateForm();
        if (!valid) {
            err = 'Invalid input';
            return;
        }

        if (casSsh.length < 1) {
            err = 'You need to initialize at least the default SSH CA before you can modify settings';
            return;
        }

        group.caSsh = caSshIdByName(caSshName);
        group.caX509 = caX509IdByName(caX509Name);

        let res = await fetchPutGroups(group.id, group);
        if (res.ok) {
            success = true;
        } else {
            let body = await res.json();
            err = body.message;
        }
    }

    async function validateForm() {
        try {
            await schema.validate(group, {abortEarly: false});
            formErrors = {};
            return true;
        } catch (err) {
            formErrors = extractFormErrors(err);
            return false;
        }
    }

</script>

<!-- Group ID -->
<div class="data">
    <div class="label">
        ID
    </div>
    <div class="groupId font-mono">
        {group.id}
    </div>
</div>

<!-- Group Name -->
<div class="data">
    <Input
            name="name"
            bind:value={group.name}
            bind:error={formErrors.name}
            placeholder="Group Name"
            on:keypress={handleKeyPress}
            on:blur={validateForm}
            bind:width
            disabled={group.name === 'default'}
    >
        NAME
    </Input>
</div>

<!-- Client Enabled -->
<div class="data" style="margin-bottom: 10px">
    <div class="label">
        Enabled
    </div>
    <div class="value">
        <Switch bind:selected={group.enabled}/>
    </div>
</div>

<!-- SSH CA Selector -->
<div class="data">
    <div class="label">
        CA SSH
    </div>
    <OptionSelect bind:value={caSshName} options={caSshOptions} bind:width/>
</div>

<!-- X509 CA Selector -->
<div class="data">
    <div class="label">
        CA X509
    </div>
    <OptionSelect bind:value={caX509Name} options={caX509Options} bind:width/>
</div>

<!-- Save Button-->
<div class="data">
    <div class="btn">
        <Button on:click={onSubmit}>SAVE</Button>
    </div>

    {#if success}
        <div class="success">
            Success
        </div>
    {/if}

    {#if err}
        <div class="mainErr err">
            {err}
        </div>
    {/if}
</div>

<div style="height: 7px"></div>

<style>
    .btn {
        width: 5rem;
    }

    .groupId {
        margin: 5px;
    }

    .data {
        display: flex;
        flex-direction: column;
        margin: 3px 10px;
    }

    .err {
        color: var(--col-err);
    }

    .mainErr, .success {
        display: flex;
        align-items: center;
        margin: 0 10px;
    }

    .label {
        min-height: 30px;
        margin: 0 5px;
        padding-top: 5px;
        display: flex;
        font-weight: bold;
    }

    .success {
        color: var(--col-ok);
    }

    .value {
        margin-left: 5px;
        margin-bottom: 5px;
        display: flex;
        align-items: center;
    }
</style>

<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import * as yup from "yup";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import {onMount} from "svelte";
    import Button from "$lib/Button.svelte";
    import {
        REGEX_CA_NAME,
        REGEX_CLIENT_NAME, SSH_CERT_TYPES,
    } from "../../../utils/constants.js";
    import IconClipboard from "$lib/icons/IconClipboard.svelte";
    import {fetchPostClientsSsh, fetchPostGroup} from "../../../utils/dataFetching.js";
    import OptionSelect from "$lib/OptionSelect.svelte";
    import Input from "$lib/inputs/Input.svelte";

    export let casSsh = [];
    export let casX509 = [];
    export let onSave;

    let show;
    let width = '23rem';

    let err = '';
    let success = false;
    let timer;

    let formErrors = {};
    let formValues = {};
    const schema = yup.object().shape({
        name: yup.string().trim().matches(REGEX_CA_NAME, 'Invalid Name'),
    });

    $: if (success) {
        timer = setTimeout(() => {
            success = false;
            show = false;
            formValues = {};
            onSave();
        }, 1500);
    }

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

    // function caSshNameById(id) {
    //     for (let ca of casSsh) {
    //         if (ca.id === id) {
    //             return fmtCaName(ca);
    //         }
    //     }
    // }

    let caSshName;
    $: caSshOptions = casSsh.map(ca => fmtCaName(ca));

    function caX509IdByName(name) {
        for (let ca of casX509) {
            if (fmtCaName(ca) === name) {
                return ca.id;
            }
        }
    }

    // function caX509NameById(id) {
    //     for (let ca of casX509) {
    //         if (ca.id === id) {
    //             return fmtCaName(ca);
    //         }
    //     }
    // }

    let caX509Name;
    // let caX509Name = caX509NameById(group.caX509);
    $: caX509Options = casX509.map(ca => fmtCaName(ca));

    onMount(() => {
        return () => clearTimeout(timer);
    });

    async function onSubmit() {
        err = '';

        const valid = await validateForm();
        if (!valid) {
            err = 'Invalid input';
            return;
        }

        let data = {
            name: formValues.name,
            caSsh: caSshIdByName(caSshName),
            caX509: caX509IdByName(caX509Name),
        }

        if (!data.caSsh || !data.caX509) {
            err = 'Set an SSH and X509 CA';
            return;
        }

        let res = await fetchPostGroup(data);
        if (res.ok) {
            success = true;
        } else {
            let body = await res.json();
            err = body.message;
        }
    }

    async function validateForm() {
        try {
            await schema.validate(formValues, {abortEarly: false});
            formErrors = {};
            return true;
        } catch (err) {
            formErrors = extractFormErrors(err);
            return false;
        }
    }

</script>

<ExpandContainer bind:show>
    <div class="header" slot="header">
        <div class="data">
            Add New Group
        </div>
    </div>

    <div slot="body">
        <!-- Group Name -->
        <div class="data">
            <Input
                    name="name"
                    bind:value={formValues.name}
                    bind:error={formErrors.name}
                    placeholder="Group Name"
                    on:blur={validateForm}
            >
                NAME
            </Input>
        </div>

        <!-- SSH CA Selector -->
        <div class="data ml-15">
            <div class="label">
                CA SSH
            </div>
            <OptionSelect bind:value={caSshName} options={caSshOptions} bind:width/>
        </div>

        <!-- X509 CA Selector -->
        <div class="data ml-15">
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
    </div>
</ExpandContainer>

<style>
    .btn {
        width: 5rem;
    }

    .data {
        display: flex;
        flex-direction: column;
        margin: 3px 10px;
    }

    .header {
        display: flex;
    }

    .err {
        color: var(--col-err);
    }

    .ml-15 {
        margin-left: 15px;
    }

    .mainErr, .success {
        display: flex;
        align-items: center;
        margin: 0 10px;
    }

    .success {
        color: var(--col-ok);
    }

    .label {
        min-height: 30px;
        width: 8rem;
        margin-right: 5px;
        padding-top: 5px;
        display: flex;
        font-weight: bold;
    }
</style>

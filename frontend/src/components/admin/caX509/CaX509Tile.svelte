<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import X509Contents from "../../x509/X509Contents.svelte";
    import Textarea from "$lib/inputs/Textarea.svelte";

    export let ca = {};

    let expandContainer;

    console.log(ca.intermediatePem);

</script>

<ExpandContainer bind:show={expandContainer}>
    <div class="header" slot="header">
        <div class="data font-mono">
            {ca.root.id}
        </div>

        <div class="data">
            {ca.root.name}
        </div>
    </div>

    <div slot="body">
        <div class="cert">
            <div class="certHeader">
                <b>Intermediate</b>
            </div>
            <X509Contents cert={ca.intermediate}/>
            <Textarea
                    rows=14
                    name="intermediatePem"
                    disabled
                    bind:value={ca.intermediatePem}
            >
            </Textarea>
        </div>
        <div class="cert">
            <div class="certHeader">
                <b>Root</b>
            </div>
            <X509Contents cert={ca.root}/>
            <Textarea
                    rows=14
                    name="intermediatePem"
                    disabled
                    bind:value={ca.rootPem}
            >
            </Textarea>
        </div>
    </div>
</ExpandContainer>

<style>
    .cert {
        margin: 10px;
        max-width: 32rem;
    }

    .certHeader {
        margin-left: .5rem;
        font-size: 1.1rem;
    }

    .data {
        display: flex;
        align-items: center;
        margin: 3px 10px;
    }

    .header {
        display: flex;
        align-items: center;
    }
</style>

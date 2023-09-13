<script>
    import {fetchGetCAsX509} from "../../../utils/dataFetching.js";
    import {onMount} from "svelte";
    import X509Contents from "../../x509/X509Contents.svelte";

    let cas = [];
    let err = '';

    onMount(() => {
        fetchCAs();
    });

    async function fetchCAs() {
        let res = await fetchGetCAsX509();
        let body = await res.json();
        if (res.ok) {
            cas = body;
        } else {
            err = body.message;
        }
    }

</script>

{err}

<div class="container">

    {#each Object.values(cas) as ca (ca.root.id)}
        <div class="cert">
            <div class="certHeader">
                <b>{`${ca.intermediate.name} - intermediate`}</b>
                <br/>
                <span class="font-mono">
                    {ca.intermediate.id}
                </span>
            </div>
            <X509Contents cert={ca.intermediate}/>
        </div>
        <div class="cert">
            <div class="certHeader">
                <b>{`${ca.root.name} - root`}</b>
                <br/>
                <span class="font-mono">
                    {ca.root.id}
                </span>
            </div>
            <X509Contents cert={ca.root}/>
        </div>
    {/each}
</div>

<style>
    .cert {
        margin: 10px;
    }

    .certHeader {
        margin-left: .5rem;
        font-size: 1.1rem;
    }

    .container {
        display: flex;
        flex: 1;
        width: 100%;
        margin: 30px;
    }
</style>

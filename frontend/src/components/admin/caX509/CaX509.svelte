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
            cas = body.casX509;
        } else {
            err = body.message;
        }
    }

</script>

{err}

<div class="container">

    {#each cas as ca (ca.serial)}
        <div class="cert">
            <div class="certHeader">
                <b>{ca.name}</b>
                <br/>
                <span class="font-mono">
                    {ca.id}
                </span>
            </div>
            <X509Contents cert={ca}/>
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

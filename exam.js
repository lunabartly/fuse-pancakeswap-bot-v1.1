
const solution = (array) => {
    
    let result = [];
    let bFlag = 0;
    for (let i = 0; i < array.length; i ++)
    {
        bFlag = 0;
        for (let j = 0; j < result.length; j ++)
        {                
            if (result[j] <= array[i])
            {
                result.splice(j, 0, array[i]);
                bFlag = 1;
                break;
            }
        }
        if (bFlag == 0)
            result.push(array[i]);
    }

    let result2 = [];

    for (let i = result.length - 1; i >= 0; i --)
    {
        result2.push(result[i]);
    }

    return result2;
};

console.log(solution([2, 2, 2, 3, 4, 4, 6, 7, 7, 7, 7, 9]));
